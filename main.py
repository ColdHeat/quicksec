import idaapi
import idautils
import idc
import re

from util import *

def get_func_start(addr):
	func = idaapi.get_func(addr)
	return func.startEA

def get_func_end(addr):
	func = idaapi.get_func(addr)
	return func.endEA

def find_calls(name):
	global functions
	try:
		addrs = [x.frm for x in idautils.XrefsTo(functions['.' + name])]
	except KeyError:
		addrs = []
	return addrs

def previous_ea(ea):
	return idautils.DecodePrecedingInstruction(ea)[0].ip

def next_ea(ea):
	size = idautils.DecodeInstruction(ScreenEA()).size
	return ea+size

def stack_offset(ea):
	ea = int(get_func_start(ea))
	while "sub" not in idc.GetDisasm(ea):
		ea = next_ea(ea)
	return hex2int(idc.GetDisasm(ea).split(',')[1].strip())

def trace_to_input(ea):
	trace = idc.GetDisasm(ea).split(',')[1].strip()
	trace = trace.replace('[', "")
	trace = trace.replace(']', "")
	
	ea = previous_ea(ea)
	instr = idc.GetDisasm(ea).split(',')[0]
	while (trace not in instr) or ('mov' not in instr):
		ea = previous_ea(ea)
		instr = idc.GetDisasm(ea).split(',')[0]

	return ea


def walk_stack(ea, func_args):
	found_args = []
	while len(found_args) < func_args:
		ea = previous_ea(ea)
		if idc.Comment(ea):
			found_args.append((ea, idc.Comment(ea)))

	return found_args

def is_register(reg):
	regs = ['ebp', 'esp', 'eax', 'ebx', 'ecx', 'edx', 'ax', 'bx', 'cx', 'dx', 'ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl']
	for x in regs:
		if x in reg:
			return True
	return False

def trace_arg(ea):
	trace = idc.GetDisasm(ea).split(';')[0].split(',')[1].strip()
	if is_register(trace):
		ea = previous_ea(ea)
		while trace not in idc.GetDisasm(ea):
			ea = previous_ea(ea)
		return ea
	else:
		if trace.isdigit():
			return int(trace)
		else:
			return trace

def hex2int(hexnum):
	return int(hexnum[:-1], 16)

def calculate_buffer_size(ea):
	instr = idc.GetDisasm(ea)
	buf = instr.split(',')[1].strip()
	if "+" in buf:
		size = hex2int(buf[buf.find('+')+1:len(buf)-1])
		return stack_offset(ea) - size
	elif "-" in buf:
		size = hex2int(buf[buf.find('-')+1:len(buf)-1])
		return stack_offset(ea) + size

BUFFER_SIZE = 0
def stack_calc(function):
	''' Calculates stack variable sizes for a given function '''
	stack_frame = GetFrame(function) 
	frame_size = GetStrucSize(stack_frame)
	frame_counter = 0
	flag = -1

	stack_vars = {}
	while frame_counter < frame_size:
		stack_var = GetMemberName(stack_frame, frame_counter)
		if stack_var != None:
			if flag != -1:
				size = frame_counter - flag
				if stack_var == " s":
					size -= 8
				if BUFFER_SIZE < size:
					stack_vars[current_member] = size
				flag = frame_counter
				current_member = stack_var
			else:
				flag = frame_counter
				current_member = stack_var
			try:
				frame_counter += GetMemberSize(stack_frame, frame_counter)
			except:
				frame_counter += 1
		else:
			frame_counter += 1
	if BUFFER_SIZE < size:
		stack_vars[current_member] = size
	return stack_vars

def test_fgets(ea):
	global bss
	args = walk_stack(ea, 3)
	arg_dict ={}
	for x in args:
		arg_dict[x[1]] = trace_arg(int(x[0]))
	arg_dict['n'] = hex2int(arg_dict['n'])

	try:
		if "offset" in arg_dict['s']:
			section = arg_dict['s'].split(' ')[1]
			arg_dict['s'] = bss[section]		
	except TypeError:
		arg_dict['s'] = calculate_buffer_size(arg_dict['s'])

	if arg_dict['s'] < arg_dict['n']:
		return True, hex(ea), arg_dict
	else:
		return False, hex(ea), arg_dict

def test_gets(ea):
	return True, hex(ea)

def test_printf(ea):
	args = walk_stack(ea, 1)
	trace = trace_arg(args[0][0])
	arg = idc.GetDisasm(trace).split(',')[1].strip()
	arg_dict = {}
	arg_dict['format'] = arg

	if "esp" in arg:
		return True, hex(ea), arg_dict
	else:
		return False, hex(ea), arg_dict


def test_strcpy(ea):
	args = walk_stack(ea, 2)
	arg_dict = {}
	for x in args:
		arg_dict[x[1]] = x[0]
	arg_dict['dest'] = calculate_buffer_size(trace_arg(arg_dict['dest']))

	arg_dict['src'] = trace_arg(arg_dict['src'])
	if "ebp" in idc.GetDisasm(arg_dict['src']) or "esp" in idc.GetDisasm(arg_dict['src']):
		arg_dict['src'] = -1
	else:
		arg_dict['src'] = trace_to_input(arg_dict['src'])

	if arg_dict['src'] == -1 or "arg" in idc.GetDisasm(arg_dict['src']):
		return True, hex(ea), arg_dict
	else:
		return False, hex(ea), arg_dict

def test_recv(ea):
	args = walk_stack(ea, 4)

	arg_dict = {}
	for x in args:
		arg_dict[x[1]] = trace_arg(x[0])
	buf = arg_dict['buf']

	try:
		buf = stack_calc(ea)['buf']
	except KeyError:
		pass

	arg_dict['buf'] = buf

	if type(arg_dict['n']) == str:
		arg_dict['n'] = hex2int(arg_dict['n'])

	if arg_dict['n'] > buf:
		return True, hex(ea), arg_dict
	else:
		return False, hex(ea), arg_dict

def test_read(ea):
	args = walk_stack(ea, 3)
	arg_dict = {}
	for x in args:
		arg_dict[x[1]] = trace_arg(x[0])
	arg_dict['nbytes'] = hex2int(arg_dict['nbytes'])
	arg_dict['buf'] = calculate_buffer_size(arg_dict['buf'])

	if arg_dict['buf'] < arg_dict['nbytes']:
		return True, hex(ea), arg_dict
	else:
		return False, hex(ea), arg_dict


### Populate BSS <Hail Chris Eagle>
start = idaapi.get_segm_by_name(".bss").startEA
end = idaapi.get_segm_by_name(".bss").endEA
item = idc.NextHead(start - 1, end)
bss = {}
while item != BADADDR:
   next = idc.NextHead(item, end)
   if next != BADADDR:
      bss[idc.Name(item)] = next - item
   else:
      bss[idc.Name(item)] = end - item
   item = next

### Populate Functions
functions = {}
for x in idautils.Functions():
    functions[idc.GetFunctionName(x)] = x


print "gets", find_calls('gets')
for x in find_calls('gets'):
	res = test_gets(x)
	print '\t', res
	if res[0]:	idc.SetColor(int(res[1], 16), CIC_ITEM, 0x0000ff)


print "fgets", find_calls('fgets')
for x in find_calls('fgets'):
	res = test_fgets(x)
	print '\t', res
	if res[0]:	idc.SetColor(int(res[1], 16), CIC_ITEM, 0x0000ff)


print "strcpy", find_calls('strcpy')
for x in find_calls('strcpy'):
	res = test_strcpy(x)
	print '\t', res
	if res[0]:	idc.SetColor(int(res[1], 16), CIC_ITEM, 0x0000ff)


print "recv", find_calls('recv')
for x in find_calls('recv'):
	res = test_recv(x)
	print '\t', res
	if res[0]:	idc.SetColor(int(res[1], 16), CIC_ITEM, 0x0000ff)


print "printf", find_calls('printf')
for x in find_calls('printf'):
	res = test_printf(x)
	print '\t', res
	if res[0]:	idc.SetColor(int(res[1], 16), CIC_ITEM, 0x0000ff)


print "read", find_calls('read')
for x in find_calls('read'):
	res = test_read(x)
	print '\t', res
	if res[0]:	idc.SetColor(res[1], CIC_ITEM, 0x0000ff)