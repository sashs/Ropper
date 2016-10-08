class Vex(object):

    @classmethod
    def use(cls, name):
        if not isinstance(name, str):
            name = name.__class__.__name__.lower()
        return getattr(cls, name, cls.dummy)

    @staticmethod
    def dummy(*args, **kwargs):
        pass


class SExpressions(Vex):

    @staticmethod
    def get(data, slice):  
        reg = data.arch.translate_register_name(data.offset, data.result_size)
        slice.regs.append(reg)  

    @staticmethod
    def load(data, slice):
        SExpressions.use(data.addr)(data.addr, slice)

    @staticmethod
    def rdtmp( data, slice):
        reg = 't%d' % data.tmp
        slice.regs.append(reg)   

    @staticmethod
    def binop(data, slice):
        SExpressions.use(data.args[1])(data.args[1], slice)
        SExpressions.use(data.args[0])(data.args[0], slice)

    @staticmethod
    def unop(data, slice):
        SExpressions.use(data.args[0])(data.args[0], slice)


class SStatements(Vex):

    @staticmethod
    def put(stmt, slice, number):
        dest = stmt.arch.translate_register_name(stmt.offset, stmt.data.result_size)
        if dest not in slice.regs:
            return

        del slice.regs[slice.regs.index(dest)]
        #stmt.pp()
        slice.instructions.append(number)
        SExpressions.use(stmt.data)(stmt.data, slice)

    @staticmethod
    def wrtmp(stmt, slice, number):
        tmp = 't'+str(stmt.tmp)
        dest = tmp
        if dest not in slice.regs:
            return

        del slice.regs[slice.regs.index(dest)]
        #stmt.pp()
        slice.instructions.append(number)
        SExpressions.use(stmt.data)(stmt.data, slice)
        

    @staticmethod
    def imark(stmt, slice, number):
        pass

class Slice(object):

    def __init__(self, reg):
        self.instructions = []
        self.regs = [reg] 


class Slicer(object):

    def slicing(self, irsb, reg):
        
        stmts = irsb.statements[::-1]
        slice = Slice(reg)
        stmt_number = 1
        for stmt in stmts:
            
            func = SStatements.use(stmt)
            func(stmt, slice, stmt_number)
            #if func != Vex.dummy:
            stmt_number += 1
            if not slice.regs:
                break
        return slice