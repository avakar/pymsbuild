from __future__ import print_function
from xml.etree import ElementTree
import sys, os, os.path, argparse, six, glob, re, tempfile
import winreg as winreg
from known_paths import get_path, FOLDERID
from appdirs import user_data_dir

from speg import peg

class Node:
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def __repr__(self):
        args = ['{}={!r}'.format(k, v) for k, v in six.iteritems(self.__dict__) if not k.startswith('_')]
        return '{}({})'.format(self.__class__.__name__, ', '.join(args))

class PropRef(Node):
    def eval_prop(self, props):
        return props.get_prop(self.name) or ''

class StringLiteral(Node):
    def eval_prop(self, props):
        return self.value

class RegistryValue(Node):
    def eval_prop(self, props):
        val = self.value.eval_prop(props)

        root, val = val.split('\\', 1)
        key, val = val.split('@', 1)

        try:
            hkey = winreg.OpenKey(winreg.__dict__[root], key)
            try:
                data, tp = winreg.QueryValueEx(hkey, val)
            finally:
                winreg.CloseKey(hkey)

        except WindowsError:
            return ''

        if tp != winreg.REG_SZ:
            return ''

        return data

class Call(Node):
    def eval_prop(self, props):
        fn = props.fns[(self.cls, self.fn_name)]
        args = [arg.eval_prop(props) for arg in self.args]

        r = fn(*args)
        if isinstance(r, bool):
            r = 'true' if r else 'false'
        return r

class Seq(Node):
    def eval_prop(self, props):
        return ''.join(item.eval_prop(props) for item in self.items)

class Exists(Node):
    def eval_cond(self, ctx):
        return ctx.file_exists(self.arg.eval_prop(ctx))

class StringCond(Node):
    def eval_cond(self, ctx):
        val = self.value.eval_prop(ctx).strip().lower()
        if val not in ('yes', 'no', 'true', 'false', ''):
            raise RuntimeError('invalid condition value: {}'.format(val))
        return val in ('yes', 'true', '')

class CmpExpr(Node):
    def eval_cond(self, ctx):
        lhs = self.lhs.eval_prop(ctx)
        rhs = self.rhs.eval_prop(ctx)

        if self.op == '==':
            return lhs == rhs
        elif self.op == '!=':
            return lhs != rhs
        elif self.op == '<=':
            return lhs <= rhs
        elif self.op == '>=':
            return lhs >= rhs
        elif self.op == '>':
            return lhs > rhs
        elif self.op == '<':
            return lhs < rhs

class LogicalExpr(Node):
    def eval_cond(self, ctx):
        lhs = self.lhs.eval_cond(ctx)
        rhs = self.rhs.eval_cond(ctx)

        if self.op == 'and':
            return lhs and rhs
        if self.op == 'or':
            return lhs or rhs

class NegExpr(Node):
    def eval_cond(self, ctx):
        return not self.sub.eval_cond(ctx)

def parse_msbuild_value(s):
    return peg(s, _p_root)

def parse_msbuild_cond(s):
    return peg(s, _p_cond)

def _p_cond_arg(p):
    with p:
        p(r'\$\(')
        _p_ws(p)
        prop_expr = _p_expr(p)
        _p_ws(p)
        p('\)')
        return prop_expr

    with p:
        p('\'')
        s = p(r"[^']*")
        p('\'')
        return parse_msbuild_value(s)

    with p:
        p(r'\(')
        _p_ws(p)
        r = p(_p_cond_arg)
        _p_ws(p)
        p(r'\)')
        return r

    val = p(r'[A-Za-z0-9\.\+\-]+')
    return StringLiteral(value=val)

def _p_cond_atom(p):
    with p:
        p('!')
        p(_p_ws)
        r = p(_p_cond_atom)
        return NegExpr(sub=r)

    with p:
        fn_name = p(_p_id)
        p(_p_ws)
        args = p(_p_fnargs)
        return StringCond(value=Call(cls='', fn_name=fn_name.lower(), args=args))

    with p:
        lhs = p(_p_cond_arg)
        p(_p_ws)
        op = p(r'==|!=|\<|\>|<=|>=')
        p(_p_ws)
        rhs = p(_p_cond_arg)
        return CmpExpr(lhs=lhs, rhs=rhs, op=op)
    with p:
        p(r'\(')
        _p_ws(p)
        r = p(_p_cond_item)
        _p_ws(p)
        p(r'\)')
        return r

    r = p(_p_cond_arg)
    return StringCond(value=r)

def _p_cond_item(p):
    with p:
        lhs = p(_p_cond_atom)
        p(_p_ws)
        op = p(r'and|or', re.I)
        p(_p_ws)
        rhs = p(_p_cond_item)
        return LogicalExpr(lhs=lhs, rhs=rhs, op=op.lower())

    return p(_p_cond_atom)

def _p_cond(p):
    r = _p_cond_item(p)
    p(p.eof)
    return r

def _p_ws(p):
    return p(r'[ \t]*')

def _p_id(p):
    return p(r'[_A-Za-z0-9\-]+')

def _p_float(p):
    return p(r'[+\-]?[0-9]+|[+\-]?[0-9]+\.[0-9]*|[+\-]?[0-9]*\.[0-9]+')

def _p_classname(p):
    return p(r'[_A-Za-z0-9\-]+(?:\.[_A-Za-z0-9\-]+)*')

def _p_fnargs(p):
    p(r'\(')
    _p_ws(p)

    args = []
    with p:
        args.append(_p_expr(p))
        _p_ws(p)
        p.commit()

        while True:
            p(',[ \t]*')
            args.append(_p_expr(p))
            _p_ws(p)
            p.commit()

    p(r'\)')
    return args

def _p_expr(p):
    with p:
        p(r'\[')
        _p_ws(p)
        cls = _p_classname(p)
        _p_ws(p)
        p(r'\][ \t]*::[ \t]*')

        fn_name = _p_id(p)
        _p_ws(p)

        args = p(_p_fnargs)
        return Call(cls=cls, fn_name=fn_name, args=args)

    with p:
        p('Registry:')
        value = p(_p_seq)
        return RegistryValue(value=value)

    with p:
        p("'")
        s = p(r"[^']+")
        p("'")
        return peg(s, _p_root)

    with p:
        p('"')
        s = p(r'[^"]+')
        p('"')
        return peg(s, _p_root)

    with p:
        p('`')
        s = p(r'[^`]+')
        p('`')
        return peg(s, _p_root)

    name = _p_id(p)

    with p:
        p(_p_ws)
        p(r'\.')
        p(_p_ws)
        fn_name = p(_p_id)
        p(_p_ws)
        p(r'\(')
        args = [PropRef(name=name)]
        with p:
            args.append(_p_expr(p))
            _p_ws(p)
            p.commit()

            while True:
                p(',[ \t]*')
                args.append(_p_expr(p))
                _p_ws(p)
                p.commit()
        p(r'\)')
        return Call(cls='', fn_name=fn_name, args=args)

    return PropRef(name=name)

def _p_prop_expr_item(p):
    with p:
        p(r'\$\(')
        _p_ws(p)
        prop_expr = _p_expr(p)
        _p_ws(p)
        p('\)')
        return prop_expr

    lit = p(r'.[^$]*', re.S)
    return StringLiteral(value=lit)

def _p_seq(p):
    r = []

    with p:
        while True:
            r.append(_p_prop_expr_item(p))
            p.commit()

    if len(r) == 0:
        return StringLiteral(value='')

    if len(r) == 1:
        return r[0]

    return Seq(items=r)

def _p_root(p):
    r = p(_p_seq)
    p(p.eof)
    return r

#z = parse_msbuild_value("""

#      {CandidateAssemblyFiles};
#      $(ReferencePath);
#      {HintPathFromItem};
#      {TargetFrameworkDirectory};
#      {Registry:$(FrameworkRegistryBase),$(TargetFrameworkVersion),$(AssemblyFoldersSuffix)$(AssemblyFoldersExConditions)};
#      {AssemblyFolders};
#      {GAC};
#      {RawFileName};
#      $(OutDir)
    
#      """)

def unns(tag, check_ns=None):
    pos = tag.find('}')
    if pos != -1 and tag[0] == '{':
        ns = tag[1:pos]
        res = tag[pos+1:]
    else:
        ns = None
        res = tag
    if check_ns is not None and check_ns != ns:
        raise RuntimeError('NS check failed')
    return res

class Item:
    def __init__(self, include, meta):
        self.include = include
        self.meta = meta

    def __repr__(self):
        return 'Item(%r, %r)' % (self.include, self.meta)

class Target:
    def __init__(self, name, fname, elem):
        self.name = name
        self.fname = fname
        self.elem = elem
        self._deps = []
        self._before = []
        self._after = []

    def __repr__(self):
        return 'Target({!r})'.format(self.name)

class Task:
    pass

class MsBuildInstance:
    def __init__(self, msbuild_ver='14.0', vs_ver='14.0'):
        self._props = {}
        self._items = {}
        self._targets = {}
        self._import_stack = []

        class EvalCtx:
            def __init__(self, inst):
                self._inst = inst
                self.fns = {
                    ('MSBuild', 'ValueOrDefault'): self._value_or_default,
                    ('System.IO.Path', 'GetFileName'): self._get_file_name,
                    ('System.IO.Path', 'GetDirectoryName'): self._get_directory_name,
                    ('System.IO.Path', 'Combine'): os.path.join,
                    ('System.IO.Path', 'GetTempPath'): self._get_temp_path,
                    ('System.String', 'IsNullOrEmpty'): lambda s: not s,
                    ('', 'StartsWith'): self._starts_with,
                    ('', 'exists'): self._exists,
                    ('', 'hastrailingslash'): self._has_trailing_slash,
                    }

            def _value_or_default(self, val, default):
                return val if val else default

            def _get_file_name(self, path):
                return os.path.split(path)[1]

            def _get_directory_name(self, path):
                return os.path.split(path)[0] + os.sep

            def _get_temp_path(self):
                return tempfile.gettempdir() + os.sep

            def _starts_with(self, this, prefix):
                return this.startswith(prefix)

            def _exists(self, path):
                return self.file_exists(path)

            def _has_trailing_slash(self, s):
                return s.endswith(os.sep)

            def get_prop(self, key):
                return self._inst.get_prop(key)

            def file_exists(self, fname):
                return os.path.exists(fname)

        self._eval_ctx = EvalCtx(self)
        self._init_predefined_props(msbuild_ver, vs_ver)

    def _load_registry_props(self, key):
        r = {}

        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
        try:
            i = 0
            while True:
                try:
                    name, data, keytype = winreg.EnumValue(key, i)
                    if keytype != winreg.REG_SZ:
                        continue
                    self.set_prop(name, self._expand_props(data))
                    i += 1
                except WindowsError:
                    break
        finally:
            winreg.CloseKey(key)

        return r

    def _escape(self, s):
        return s

    def _init_predefined_props(self, msbuild_ver, vs_ver):
        for k, v in six.iteritems(os.environ):
            self.set_prop(k, self._escape(v))

        hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\MSBuild\ToolsVersions\{}'.format(msbuild_ver))
        try:
            bin_path, tp = winreg.QueryValueEx(hkey, 'MSBuildToolsRoot')
        finally:
            winreg.CloseKey(hkey)

        if tp != winreg.REG_SZ:
            raise RuntimeError('Invalid registry value type')

        self._props.update({
            'msbuildassemblyversion': msbuild_ver,
            'msbuildextensionspath': bin_path,
            'msbuildextensionspath32': bin_path,
            'msbuildextensionspath64': bin_path,
            'msbuildprogramfiles32': get_path(FOLDERID.ProgramFilesX86),
            'msbuildprogramfiles64': get_path(FOLDERID.ProgramFilesX64),
            'msbuildprogramfiles': get_path(FOLDERID.ProgramFiles),
            'msbuildtoolsversion': msbuild_ver,
            'msbuilduserextensionspath': user_data_dir('MSBuild', 'Microsoft', roaming=True),
            'visualstudioversion': vs_ver,
            })

        props = self._load_registry_props(r'SOFTWARE\Microsoft\MSBuild\ToolsVersions\{}'.format(msbuild_ver))
        props = self._load_registry_props(r'SOFTWARE\Microsoft\MSBuild\ToolsVersions\{}\{}'.format(msbuild_ver, vs_ver))

    def get_prop(self, name, default=None):
        name = name.lower()
        if name == 'msbuildthisfile':
            return os.path.split(self._import_stack[-1])[1]
        if name == 'msbuildthisfiledirectory':
            return os.path.split(self._import_stack[-1])[0] + os.sep
        if name == 'msbuildthisfileextension':
            return os.path.splitext(self._import_stack[-1])[1]
        if name == 'msbuildthisfilefullpath':
            return self._import_stack[-1]
        if name == 'msbuildthisfilename':
            return os.path.splitext(os.path.split(self._import_stack[-1])[1])[0]
        if name == 'msbuildprojectfullpath':
            return self._import_stack[0]
        if name == 'msbuildprojectfile':
            return os.path.split(self._import_stack[0])[1]
        if name == 'msbuildprojectextension':
            return os.path.splitext(self._import_stack[0])[1]
        if name == 'msbuildprojectname':
            return os.path.splitext(os.path.split(self._import_stack[0])[1])[0]
        if name == 'msbuildprojectdirectory':
            return os.path.split(self._import_stack[0])[0] + os.sep
        return self._props.get(name, default)

    def set_prop(self, name, value):
        name = name.lower()
        self._props[name] = value

    def import_proj(self, fname, parent=None):
        if parent:
            fname = os.path.normpath(os.path.join(os.path.split(parent)[0], fname))

        projs = glob.glob(fname)
        if not projs:
            print('#warning cannot find project {!r}'.format(fname))

        for proj in projs:
            self._import_proj_impl(proj, parent)

    def resolve_targets(self):
        def split_list(s):
            s = self._expand_props(s)
            r = (val.strip() for val in s.split(';'))
            return [val for val in r if val]

        new_targets = {}
        def find_target(name):
            r = self._targets.get(name)
            if r is None:
                r = new_targets.get(name)

            if r is None:
                r = Target(name, None, None)
                new_targets[name] = r

            return r

        for name, target in six.iteritems(self._targets):
            for o in split_list(target.elem.attrib.get('BeforeTargets', '')):
                find_target(o)._before.append(target)
            for o in split_list(target.elem.attrib.get('AfterTargets', '')):
                find_target(o)._after.append(target)
            for o in split_list(target.elem.attrib.get('DependsOnTargets', '')):
                target._deps.append(find_target(o))

        self._targets.update(new_targets)

        for tgt in six.itervalues(self._targets):
            tgt._deps.extend(tgt._before)
            tgt._deps.extend(tgt._after)

            seen = set()
            new_deps = []
            for dep in tgt._deps:
                if dep not in seen:
                    new_deps.append(dep)
                    seen.add(dep)
            tgt._deps = new_deps

    def _import_proj_impl(self, fname, parent):
        self._import_stack.append(fname)

        doc = ElementTree.parse(fname)
        root = doc.getroot()
        if root.tag != '{http://schemas.microsoft.com/developer/msbuild/2003}Project':
            raise RuntimeError('Project tag expected as root.')

        def parse_project(root):
            for group in root:
                if group.tag == '{http://schemas.microsoft.com/developer/msbuild/2003}PropertyGroup':
                    for prop in group:
                        key = unns(prop.tag)
                        if not self._eval_cond(prop.get('Condition')):
                            continue
                        self.set_prop(unns(prop.tag), self._expand_props(prop.text or ''))
                elif group.tag == '{http://schemas.microsoft.com/developer/msbuild/2003}ItemGroup':
                    for item in group:
                        if not self._eval_cond(item.get('Condition')):
                            continue
                        self._items.setdefault(unns(item.tag), []).append(Item(item.get('Include'), item))
                elif group.tag == '{http://schemas.microsoft.com/developer/msbuild/2003}Import':
                    if not self._eval_cond(group.get('Condition')):
                        continue
                    proj = group.get('Project')
                    self.import_proj(self._expand_props(proj), fname)
                elif group.tag == '{http://schemas.microsoft.com/developer/msbuild/2003}ImportGroup':
                    if not self._eval_cond(group.get('Condition')):
                        continue
                    for item in group:
                        if not self._eval_cond(item.get('Condition')):
                            continue
                        if item.tag != '{http://schemas.microsoft.com/developer/msbuild/2003}Import':
                            raise RuntimeError('Only Import tags can be nested in ImportGroup')
                        self.import_proj(self._expand_props(item.get('Project')), fname)
                elif group.tag == '{http://schemas.microsoft.com/developer/msbuild/2003}Target':
                    name = group.attrib['Name']
                    self._targets[name] = Target(name, fname, group)
                elif group.tag == '{http://schemas.microsoft.com/developer/msbuild/2003}ItemDefinitionGroup':
                    # XXX
                    pass
                elif group.tag == '{http://schemas.microsoft.com/developer/msbuild/2003}UsingTask':
                    # XXX
                    pass
                elif group.tag == '{http://schemas.microsoft.com/developer/msbuild/2003}Choose':
                    for elem in group:
                        if elem.tag == '{http://schemas.microsoft.com/developer/msbuild/2003}When':
                            if not self._eval_cond(elem.get('Condition')):
                                continue
                            parse_project(elem)
                            break
                        elif elem.tag == '{http://schemas.microsoft.com/developer/msbuild/2003}Otherwise':
                            parse_project(elem)
                            break
                        else:
                            raise RuntimeError('unexpected: {}'.format(elem.tag))
                else:
                    print('#warning unknown tag: {}'.format(group.tag))

        parse_project(root)
        self._import_stack.pop()

    def _expand_props(self, s, keep_unresolved=False):
        parsed = parse_msbuild_value(s)
        return parsed.eval_prop(self._eval_ctx)

    def _eval_cond(self, cond):
        if cond:
            cond = cond.strip()

        if not cond:
            return True

        parsed = parse_msbuild_cond(cond)
        ret = parsed.eval_cond(self._eval_ctx)
        return ret

def _main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--msbuild-ver', default='14.0')
    ap.add_argument('--vs-ver', default='14.0')
    ap.add_argument('project')
    ap.add_argument('props', nargs='*')
    args = ap.parse_args()

    msbuild = MsBuildInstance(args.msbuild_ver, args.vs_ver)

    for arg in args.props:
        key, value = arg.split('=', 1)
        msbuild.set_prop(key, value)

    msbuild.import_proj(args.project)
    msbuild.resolve_targets()

    r = ['digraph {\n']

    q = [msbuild._targets['Build']]
    seen = set(q)
    while q:
        cur = q.pop()
        for dep in cur._deps:
            r.append('{} -> {};\n'.format(cur.name, dep.name))
            if dep not in seen:
                seen.add(dep)
                q.append(dep)

    r.append('}\n')

    # toposort
    to = []
    marked = set()
    def visit(node):
        marked.add(node)
        for dep in node._deps:
            if dep not in marked:
                visit(dep)
        to.append(node)

    for tgt in seen:
        if tgt in marked:
            continue
        visit(tgt)

    for tgt in to:
        sys.stdout.write('{}\n'.format(tgt.fname))
        sys.stdout.buffer.write(ElementTree.tostring(tgt.elem))

    #print(''.join(r))
    
    return 0

if __name__ == '__main__':
    sys.exit(_main())


    print(properties['BuildCompileAction'])

    #for t in sorted(targets.keys()):
    #    print t

    built = set()
    q = [('Build', None)]
    while q:
        cur, super = q[0]

        if cur not in targets:
            built.add(cur)
            q.pop(0)
            continue

        t = targets[cur]
        cond = t.get('Condition', '')
        if not _eval_cond(cond):
            built.add(cur)
            q.pop(0)
            continue

        has_deps = False
        deps = filter(None, [dep.strip() for dep in _expand(t.get('DependsOnTargets', '')).split(';')])
        for dep in reversed(deps):
            if dep in built:
                continue
            if dep in q:
                q.remove(dep)
            q.insert(0, (dep, cur))
            has_deps = True

        if has_deps:
            continue

        print('{} {} {}'.format(cur, super, targets[cur].fname))
        built.add(cur)
        q.pop(0)

    #for key, value in sorted(properties.iteritems()):
    #    print key, value
    #for item in items['ClCompile']:
    #    print item.include

    #for key, value in sorted(targets.iteritems()):
    #    print key, value
    #    for task in value.tasks:
    #        print '    ', task.name

