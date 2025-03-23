import sys, os
import struct
import hashlib
import re

import ida_allins
import ida_auto
import ida_bytes
import ida_diskio
import ida_entry
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_nalt
import ida_name
import ida_netnode
import ida_search
import ida_segment
import ida_typeinf
import ida_ua
import ida_xref

import idc
import idautils

from collections import OrderedDict
from io import BytesIO
from pprint import pprint

def as_uint8(x):
	return x & 0xFF

def as_uint16(x):
	return x & 0xFFFF

def as_uint32(x):
	return x & 0xFFFFFFFF

def as_uint64(x):
	return x & 0xFFFFFFFFFFFFFFFF

def align_up(x, alignment):
	return (x + (alignment - 1)) & ~(alignment - 1)

def align_down(x, alignment):
	return x & ~(alignment - 1)

def hexdump(data, cols=16, addr=0):
	byte_filter = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
	lines = []

	for c in range(0, len(data), cols):
		chunk = data[c:c + cols]
		hex_data = ' '.join(['%02x' % x for x in chunk])
		printable = ''.join(['%s' % ((x <= 127 and byte_filter[x]) or '.') for x in chunk])
		lines.append('%08x %-*s %s' % (addr + c, cols * 3, hex_data, printable))

	print('\n'.join(lines))

def determine_simple_type(type_decl):
	return {
		'uint8_t': 'uint8_t',
		'__uint8': 'uint8_t',
		'unsigned int8_t': 'uint8_t',
		'unsigned __int8': 'uint8_t',
		'unsigned char': 'uint8_t',
		'int8_t': 'int8_t',
		'__int8': 'int8_t',
		'signed int8_t': 'int8_t',
		'signed __int8': 'int8_t',
		'char': 'int8_t',

		'uint16_t': 'uint16_t',
		'__uint16': 'uint16_t',
		'unsigned int16_t': 'uint16_t',
		'unsigned __int16': 'uint16_t',
		'unsigned short': 'uint16_t',
		'int16_t': 'int16_t',
		'__int16': 'int16_t',
		'signed int16_t': 'int16_t',
		'signed __int16': 'int16_t',
		'short': 'int16_t',

		'uint32_t': 'uint32_t',
		'__uint32': 'uint32_t',
		'unsigned int32_t': 'uint32_t',
		'unsigned __int32': 'uint32_t',
		'unsigned int': 'uint32_t',
		'int32_t': 'int32_t',
		'__int32': 'int32_t',
		'signed int32_t': 'int32_t',
		'signed __int32': 'int32_t',
		'int': 'int32_t',

		'uint64_t': 'uint64_t',
		'__uint64': 'uint64_t',
		'unsigned int64_t': 'uint64_t',
		'unsigned __int64': 'uint64_t',
		'unsigned long': 'uint64_t',
		'unsigned long long': 'uint64_t',
		'int64_t': 'int64_t',
		'__int64': 'int64_t',
		'signed int64_t': 'int64_t',
		'signed __int64': 'int64_t',
		'long': 'int64_t',
		'long long': 'int64_t',
	}.get(type_decl, None)

def unpack_by_type(data, size, type_info):
	assert len(data) >= size

	initial_type_name = type_info.dstr()
	initial_final_type_name = type_info.get_final_type_name()

	data = data[:size]
	endian = '>' if ida_ida.inf_is_be() else '<'

	fmt = None
	value = None

	if type_info.is_array():
		type_info = type_info.get_array_element()
		type_name = type_info.dstr()
		final_type_name = type_info.get_final_type_name()
		if final_type_name is None:
			final_type_name = type_name
		final_type_name = determine_simple_type(final_type_name)
	else:
		type_name = initial_type_name
		final_type_name = initial_final_type_name
		if final_type_name is None:
			final_type_name = type_name
		final_type_name = determine_simple_type(final_type_name)

	if final_type_name == 'uint8_t':
		fmt = 'B'
	elif final_type_name == 'int8_t':
		fmt = 'b'
	elif final_type_name == 'uint16_t':
		fmt = 'H'
	elif final_type_name == 'int16_t':
		fmt = 'h'
	elif final_type_name == 'uint32_t':
		fmt = 'I'
	elif final_type_name == 'int32_t':
		fmt = 'i'
	elif final_type_name == 'uint64_t':
		fmt = 'Q'
	elif final_type_name == 'int64_t':
		fmt = 'q'
	elif final_type_name == 'float':
		fmt = 'f'
	elif final_type_name == 'double':
		fmt = 'd'
	elif type_info.is_ptr():
		fmt = 'Q'
	else:
		# XXX: Need to handle this manually.
		value = data

	if fmt is not None:
		stride = struct.calcsize(fmt)
		count = size // stride
		if count > 1:
			value = struct.unpack('%s%d%s' % (endian, count, fmt), data)
			value = list(value)
		elif count == 1:
			value = struct.unpack('%s%s' % (endian, fmt), data)[0]
		else:
			value = []

	return value, size

def get_struct_size(name):
	assert isinstance(name, str)

	type_id = ida_typeinf.get_named_type_tid(name)
	type_info = ida_typeinf.tinfo_t()
	if type_id == ida_idaapi.BADADDR or not type_info.get_type_by_tid(type_id) or not type_info.is_udt():
		raise RuntimeError('Structure not found: %s' % name)

	return type_info.get_size()

def parse_struct(name, data):
	assert isinstance(name, str)
	assert isinstance(data, bytes)

	type_id = ida_typeinf.get_named_type_tid(name)
	type_info = ida_typeinf.tinfo_t()
	if type_id == ida_idaapi.BADADDR or not type_info.get_type_by_tid(type_id) or not type_info.is_udt():
		raise RuntimeError('Structure not found: %s' % name)

	total_size = type_info.get_size()
	assert len(data) >= total_size

	udt = ida_typeinf.udt_type_data_t()
	assert type_info.get_udt_details(udt)
	count = type_info.get_udt_nmembers()

	#if type_info.is_typedef():
	#	return None

	fields = OrderedDict()

	for idx, udm in enumerate(udt):
		if udm.is_gap():
			continue

		member_name = udm.name
		member_offset = udm.offset // 8
		member_size = udm.size // 8
		member_type_info = udm.type

		value_data = data[member_offset:member_offset + member_size]

		info = unpack_by_type(value_data, member_size, member_type_info)

		fields[member_name] = info[0]

	return fields

def check_insn_format(ea, mnem, operands=[]):
	if ida_ua.print_insn_mnem(ea).lower() != mnem.lower():
		return False

	match = True

	for i, (needed_type, needed_value) in enumerate(operands):
		if needed_type is None:
			continue
		real_type = idc.get_operand_type(ea, i)
		if real_type != needed_type:
			match = False
			break

		if needed_value is None:
			continue
		if isinstance(needed_value, str):
			# XXX: Cannot use ida_ua.print_operand because it returns garbage data.
			value = idc.print_operand(ea, i).lower().strip()
			needed_value = needed_value.lower().strip()
		else:
			value = idc.get_operand_value(ea, i)

		if value != needed_value:
			match = False
			break

	return match

def read_cstring_at(ea, encoding='utf-8'):
	length = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C)
	data = ida_bytes.get_strlit_contents(ea, length, ida_nalt.STRTYPE_C)
	if encoding is not None:
		data = data.decode(encoding)
	return data

def refresh_views():
	ida_kernwin.refresh_idaview_anyway()

	widget = ida_kernwin.get_current_widget()
	vu = ida_hexrays.get_widget_vdui(widget)
	if vu:
		vu.refresh_ctext()

def sha1(data):
	return hashlib.sha1(data).digest()

class ObjectInfo(object):
	AUTO_EXPORT = (1 << 0)
	WEAK_EXPORT = (1 << 1)
	LOOSE_IMPORT = (1 << 3)

	CANT_STOP = (1 << 0)
	EXCLUSIVE_LOAD = (1 << 1)
	EXCLUSIVE_START = (1 << 2)
	CAN_RESTART = (1 << 3)
	CAN_RELOCATE = (1 << 4)
	CANT_SHARE = (1 << 5)

	ATTR_MASK = 0xFFFFFFFFFFFF
	EXPORT_ATTR_MASK = AUTO_EXPORT | WEAK_EXPORT | LOOSE_IMPORT
	IMPORT_ATTR_MASK = EXCLUSIVE_LOAD | CANT_STOP | CAN_RESTART | EXCLUSIVE_START | CANT_SHARE | CAN_RELOCATE

	ENCODING_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-'
	DECODING_CHARSET = bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF3EFF3FFFFF3435363738393A3B3C3DFFFFFFFFFFFFFF000102030405060708090A0B0C0D0E0F10111213141516171819FFFFFFFFFFFF1A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233FFFFFFFFFF')

	NID_SUFFIX = bytes.fromhex('518D64A635DED8C1E6B039B1C3E55230')

	def __init__(self):
		self.id = None
		self.version_major = None
		self.version_minor = None
		self.name_offset = None
		self.name = None
		self.attrs = None
		self.is_export = None

	def set_info(self, value, is_export=False):
		self.id = ObjectInfo.obj_id(value)
		self.version_major, self.version_minor = ObjectInfo.obj_version(value)
		self.name_offset = ObjectInfo.obj_name_offset(value)
		self.is_export = is_export

	def set_attr(self, value):
		self.id = ObjectInfo.obj_id(value)
		self.attrs = ObjectInfo.obj_attrs(value)

		if self.is_export:
			if self.attrs & (~ObjectInfo.EXPORT_ATTR_MASK):
				ida_kernwin.warning('Unsupported export attributes: %s' % ObjectInfo.stringify_attrs(self.attrs, True))
		else:
			if self.attrs & (~ObjectInfo.IMPORT_ATTR_MASK):
				ida_kernwin.warning('Unsupported import attributes: %s' % ObjectInfo.stringify_attrs(self.attrs, False))

	def update_name(self, base_ea):
		assert self.name_offset is not None
		self.name = read_cstring_at(base_ea + self.name_offset)

	def __repr__(self):
		if self.id is not None:
			return 'ObjectInfo(id=0x%x, version=%02d.%02d, name=%s, attrs=%s, is_export=%d)' % (self.id, self.version_major, self.version_minor, self.name if self.name else 'nil', ObjectInfo.stringify_attrs(self.attrs, self.is_export), self.is_export)
		else:
			return 'n/a'

	@staticmethod
	def calculate_nid(x):
		return sha1(x.encode('ascii') + ObjectInfo.NID_SUFFIX)[:8]

	@staticmethod
	def encode_nid(x):
		enc, = struct.unpack('<Q', ObjectInfo.calculate_nid(x))

		result = ObjectInfo.ENCODING_CHARSET[(enc & 0xF) << 2]
		tmp = enc >> 4
		while tmp != 0:
			result += ObjectInfo.ENCODING_CHARSET[tmp & 0x3F]
			tmp = tmp >> 6

		return result[::-1], enc

	@staticmethod
	def decode_nid(x):
		size = len(x)
		assert size == 11

		result = 0

		for i in range(size):
			idx = ord(x[i])
			assert idx < len(ObjectInfo.DECODING_CHARSET)
			value = ObjectInfo.DECODING_CHARSET[idx]
			assert value != 0xFF

			if i == size - 1:
				result = (result << 4) | (value >> 2)
			else:
				result = (result << 6) | value

		return result

	@staticmethod
	def encode_obj_id(x):
		result = ObjectInfo.ENCODING_CHARSET[(x & 0xF) << 2]
		tmp = x >> 4
		while tmp != 0:
			result += ObjectInfo.ENCODING_CHARSET[tmp & 0x3F]
			tmp = tmp >> 6

		return result[::-1]

	@staticmethod
	def decode_obj_id(x):
		size = len(x)
		assert size <= 4

		result = 0

		for i in range(size):
			idx = ord(x[i])
			assert idx < len(ObjectInfo.DECODING_CHARSET)
			value = ObjectInfo.DECODING_CHARSET[idx]
			assert value != 0xFF
			result = (result << 6) | value

		return result

	@staticmethod
	def obj_id(value):
		return (value >> 48) & 0xFFFF

	@staticmethod
	def obj_attrs(value):
		return (value & ObjectInfo.ATTR_MASK)

	@staticmethod
	def obj_name_offset(value):
		return value & ((1 << 32) - 1)

	@staticmethod
	def obj_version(value):
		major, minor = (value >> 32) & 0xFF, (value >> 40) & 0xFF
		return major, minor

	@staticmethod
	def stringify_attrs(attrs, is_export):
		if not attrs:
			return 'none'

		result = []

		if is_export:
			if attrs & ObjectInfo.AUTO_EXPORT:
				result.append('AUTO_EXPORT')
				attrs &= ~ObjectInfo.AUTO_EXPORT
			if attrs & ObjectInfo.WEAK_EXPORT:
				result.append('WEAK_EXPORT')
				attrs &= ~ObjectInfo.WEAK_EXPORT
			if attrs & ObjectInfo.LOOSE_IMPORT:
				result.append('LOOSE_IMPORT')
				attrs &= ~ObjectInfo.LOOSE_IMPORT
		else:
			if attrs & ObjectInfo.CANT_STOP:
				result.append('CANT_STOP')
				attrs &= ~ObjectInfo.CANT_STOP
			if attrs & ObjectInfo.EXCLUSIVE_LOAD:
				result.append('EXCLUSIVE_LOAD')
				attrs &= ~ObjectInfo.EXCLUSIVE_LOAD
			if attrs & ObjectInfo.EXCLUSIVE_START:
				result.append('EXCLUSIVE_START')
				attrs &= ~ObjectInfo.EXCLUSIVE_START
			if attrs & ObjectInfo.CAN_RESTART:
				result.append('CAN_RESTART')
				attrs &= ~ObjectInfo.CAN_RESTART
			if attrs & ObjectInfo.CAN_RELOCATE:
				result.append('CAN_RELOCATE')
				attrs &= ~ObjectInfo.CAN_RELOCATE
			if attrs & ObjectInfo.CANT_SHARE:
				result.append('CANT_SHARE')
				attrs &= ~ObjectInfo.CANT_SHARE
		if attrs != 0:
			result.append('0x%x' % attrs)

		return '|'.join(result)

def load_known_nids(file_name):
	nids = {}

	file_path = os.path.join(ida_diskio.idadir(ida_diskio.CFG_SUBDIR), file_name)
	if not os.path.isfile(file_path):
		ida_kernwin.warning('NID database not found: %s' % file_path)
		return nids

	with open(file_path, 'r') as f:
		for line in f.readlines():
			line = line.rstrip('\r\n').strip()
			if not line:
				continue

			name = line.split(':')
			if name:
				name = name[0]
			else:
				continue

			nid_ascii, nid = ObjectInfo.encode_nid(name)
			nids[nid] = name

			# Try to prepend underscore symbol to symbol, thus getting a new one.
			if name.startswith('_'):
				name = name[1:]
			name = '_' + name
			nid_ascii, nid = ObjectInfo.encode_nid(name)
			nids[nid] = name

	return nids

class ElfUtil(object):
	# Node and tags to find corresponding net node.
	ELF_NODE = '$ elfnode'

	ELF_PHT_TAG = 'p'
	ELF_SHT_TAG = 's'

	# File types.
	ET_LOOS = 0xFE00
	ET_HIOS = 0xFEFF
	ET_SCE_EXEC_ASLR = ET_LOOS + 0x10
	ET_SCE_DYNAMIC = ET_LOOS + 0x18

	# Segment types.
	PT_LOAD = 0x1
	PT_DYNAMIC = 0x2
	PT_NOTE = 0x4
	PT_TLS = 0x7
	PT_GNU_RELRO = 0x6474E552
	PT_GNU_EH_FRAME = 0x6474E550
	PT_SCE_PROCPARAM = 0x61000001
	PT_SCE_MODULE_PARAM = 0x61000002
	PT_SCE_COMMENT = 0x6FFFFF00
	PT_SCE_VERSION = 0x6FFFFF01

	# Segment flags.
	PF_NONE = 0x0
	PF_EXEC = 0x1
	PF_WRITE = 0x2
	PF_READ = 0x4
	PF_READ_WRITE = PF_READ | PF_WRITE

	# Supported dynamic tags.
	DT_LOOS = 0x60000000
	DT_HIOS = 0x6FFFFFFF
	DT_NULL = 0x0
	DT_NEEDED = 0x1
	DT_PLTGOT = 0x3
	DT_INIT = 0xC
	DT_FINI = 0xD
	DT_SONAME = 0xE
	DT_TEXTREL = 0x16
	DT_SCE_IDTABENTSZ = DT_LOOS + 0x5
	DT_SCE_FINGERPRINT = DT_LOOS + 0x1000007
	DT_SCE_ORIGINAL_FILENAME = DT_LOOS + 0x1000009
	DT_SCE_MODULE_INFO = DT_LOOS + 0x100000D
	DT_SCE_NEEDED_MODULE = DT_LOOS + 0x100000F
	DT_SCE_MODULE_ATTR = DT_LOOS + 0x1000011
	DT_SCE_EXPORT_LIB = DT_LOOS + 0x1000013
	DT_SCE_IMPORT_LIB = DT_LOOS + 0x1000015
	DT_SCE_EXPORT_LIB_ATTR = DT_LOOS + 0x1000017
	DT_SCE_IMPORT_LIB_ATTR = DT_LOOS + 0x1000019
	DT_61000027 = DT_LOOS + 0x1000027 # TODO: Is it related to PLTGOT?
	DT_SCE_ORIGINAL_FILENAME_PPR = DT_LOOS + 0x1000041
	DT_SCE_MODULE_INFO_PPR = DT_LOOS + 0x1000043
	DT_SCE_NEEDED_MODULE_PPR = DT_LOOS + 0x1000045
	DT_SCE_IMPORT_LIB_PPR = DT_LOOS + 0x1000047
	DT_SCE_EXPORT_LIB_PPR = DT_LOOS + 0x1000049

	# Skipped dynamic tags.
	DT_PLTRELSZ = 0x2
	DT_HASH = 0x4
	DT_STRTAB = 0x5
	DT_SYMTAB = 0x6
	DT_RELA = 0x7
	DT_RELASZ = 0x8
	DT_RELAENT = 0x9
	DT_STRSZ = 0xA
	DT_SYMENT = 0xB
	DT_PLTREL = 0x14
	DT_DEBUG = 0x15
	DT_JMPREL = 0x17
	DT_INIT_ARRAY = 0x19
	DT_FINI_ARRAY = 0x1A
	DT_INIT_ARRAYSZ = 0x1B
	DT_FINI_ARRAYSZ = 0x1C
	DT_PREINIT_ARRAY = 0x20
	DT_PREINIT_ARRAYSZ = 0x21
	DT_61000025 = DT_LOOS + 0x1000025
	DT_61000029 = DT_LOOS + 0x1000029
	DT_6100002B = DT_LOOS + 0x100002B
	DT_6100002D = DT_LOOS + 0x100002D
	DT_6100002F = DT_LOOS + 0x100002F
	DT_61000031 = DT_LOOS + 0x1000031
	DT_61000033 = DT_LOOS + 0x1000033
	DT_61000035 = DT_LOOS + 0x1000035
	DT_61000037 = DT_LOOS + 0x1000037
	DT_61000039 = DT_LOOS + 0x1000039
	DT_6100003B = DT_LOOS + 0x100003B
	DT_SCE_HASHSZ = DT_LOOS + 0x100003D
	DT_SCE_SYMTABSZ = DT_LOOS + 0x100003F
	DT_RELACOUNT = DT_LOOS + 0xFFFFFF9
	DT_FLAGS_1 = DT_LOOS + 0xFFFFFFB

	# Obsoleted dynamic tags.
	DT_SYMBOLIC = 0x10
	DT_FLAGS = 0x1E

	# Unsupported dynamic tags.
	DT_RPATH = 0xF
	DT_REL = 0x11
	DT_RELSZ = 0x12
	DT_RELENT = 0x13
	DT_BIND_NOW = 0x18
	DT_RUNPATH = 0x1D
	DT_ENCODING = 0x1F
	DT_61000008 = DT_LOOS + 0x1000008
	DT_6100000A = DT_LOOS + 0x100000A
	DT_6100000B = DT_LOOS + 0x100000B
	DT_6100000C = DT_LOOS + 0x100000C
	DT_6100000E = DT_LOOS + 0x100000E
	DT_61000010 = DT_LOOS + 0x1000010
	DT_61000012 = DT_LOOS + 0x1000012
	DT_61000014 = DT_LOOS + 0x1000014
	DT_61000016 = DT_LOOS + 0x1000016
	DT_61000018 = DT_LOOS + 0x1000018
	DT_6100001A = DT_LOOS + 0x100001A
	DT_6100001B = DT_LOOS + 0x100001B
	DT_6100001C = DT_LOOS + 0x100001C
	DT_SCE_STUB_MODULE_NAME = DT_LOOS + 0x100001D
	DT_6100001E = DT_LOOS + 0x100001E
	DT_SCE_STUB_MODULE_VERSION = DT_LOOS + 0x100001F
	DT_61000020 = DT_LOOS + 0x1000020
	DT_SCE_STUB_LIBRARY_NAME = DT_LOOS + 0x1000021
	DT_61000022 = DT_LOOS + 0x1000022
	DT_SCE_STUB_LIBRARY_VERSION = DT_LOOS + 0x1000023
	DT_61000024 = DT_LOOS + 0x1000024
	DT_61000026 = DT_LOOS + 0x1000026
	DT_61000028 = DT_LOOS + 0x1000028
	DT_6100002A = DT_LOOS + 0x100002A
	DT_6100002C = DT_LOOS + 0x100002C
	DT_6100002E = DT_LOOS + 0x100002E
	DT_61000030 = DT_LOOS + 0x1000030
	DT_61000032 = DT_LOOS + 0x1000032
	DT_61000034 = DT_LOOS + 0x1000034
	DT_61000036 = DT_LOOS + 0x1000036
	DT_61000038 = DT_LOOS + 0x1000038
	DT_6100003A = DT_LOOS + 0x100003A
	DT_6100003C = DT_LOOS + 0x100003C
	DT_6100003E = DT_LOOS + 0x100003E
	DT_61000040 = DT_LOOS + 0x1000040
	DT_61000042 = DT_LOOS + 0x1000042
	DT_61000044 = DT_LOOS + 0x1000044
	DT_61000046 = DT_LOOS + 0x1000046
	DT_61000048 = DT_LOOS + 0x1000048

	# Filler for .sce_padding.
	SCE_PADDING_SIZE = 0x10
	SCE_PADDING = b'\xCC' * SCE_PADDING_SIZE

	# Magics for sceProcessParam and sceModuleParam structures.
	SCE_PROCESS_PARAM_MAGIC = b'ORBI'
	SCE_MODULE_PARAM_MAGIC = b'\xBF\xF4\x13\x3C'

	_DT_STR_MAP = {}

	def __init__(self):
		self.elf_node = ida_netnode.netnode(ElfUtil.ELF_NODE)

		if not self.is_inited():
			return

		#print('Parsing elf header.')
		self._parse_ehdr()

		#print('Parsing program headers.')
		self._parse_phdrs()

		#print('Parsing section headers.')
		self._parse_shdrs()

	def find_phdr_by_type(self, type_id, index=0):
		phdrs = []

		for i, phdr in enumerate(self.phdrs):
			p_type = ElfUtil.phdr_type(phdr)
			if p_type != type_id:
				continue
			phdrs.append(phdr)

		return phdrs[index] if index < len(phdrs) else None

	def find_phdr_by_seg(self, seg):
		if not seg:
			return None

		idx = ida_segment.get_segm_num(seg.start_ea)

		#print('Segment #%03d (start=0x%x, end=0x%0x, perm=0x%x)' % (idx, seg.start_ea, seg.end_ea, seg.perm))

		# Try to find a program header which boundaries are exactly the same as in the segment.
		#print('Doing first pass (exact).')
		for i, phdr in enumerate(self.phdrs):
			if self._match_phdr_boundaries_with_seg(i, phdr, seg, True):
				return phdr

		# Now try to find a program header which boundaries includes the segment boundaries.
		#print('Doing second pass (inexact).')
		for i, phdr in enumerate(self.phdrs):
			if self._match_phdr_boundaries_with_seg(i, phdr, seg, False):
				return phdr

		return None

	def is_inited(self):
		if self.elf_node.valobj() is None:
			return False
		node = ida_netnode.netnode(ps5_elf_plugin_t.PROSPERO_NET_NODE)
		return ida_netnode.exist(node)

	@staticmethod
	def phdr_type(phdr):
		for name in ['p_type', '_p_type', '__p_type']:
			if name in phdr:
				return phdr[name]
		return None

	@staticmethod
	def stringify_phdr_type(type_id):
		return {
			ElfUtil.PT_LOAD: 'PT_LOAD',
			ElfUtil.PT_DYNAMIC: 'PT_DYNAMIC',
			ElfUtil.PT_NOTE: 'PT_NOTE',
			ElfUtil.PT_TLS: 'PT_TLS',
			ElfUtil.PT_GNU_RELRO: 'PT_GNU_RELRO',
			ElfUtil.PT_GNU_EH_FRAME: 'PT_GNU_EH_FRAME',
			ElfUtil.PT_SCE_PROCPARAM: 'PT_SCE_PROCPARAM',
			ElfUtil.PT_SCE_MODULE_PARAM: 'PT_SCE_MODULE_PARAM',
			ElfUtil.PT_SCE_COMMENT: 'PT_SCE_COMMENT',
			ElfUtil.PT_SCE_VERSION: 'PT_SCE_VERSION',
		}.get(type_id, '0x%08x' % type_id)

	@staticmethod
	def stringify_phdr_flags(flags):
		result = []
		if flags == ElfUtil.PF_NONE:
			result.append('PF_NONE')
		else:
			if flags & ElfUtil.PF_READ:
				result.append('PF_READ')
			if flags & ElfUtil.PF_WRITE:
				result.append('PF_WRITE')
			if flags & ElfUtil.PF_EXEC:
				result.append('PF_EXEC')
		return '|'.join(result)

	@staticmethod
	def stringify_dyn_tag(tag):
		return ElfUtil._DT_STR_MAP.get(tag, '0x%x' % tag)

	@staticmethod
	def phdr_flags_from_perm(perm):
		flags = 0
		if perm & ida_segment.SEGPERM_READ:
			flags |= ElfUtil.PF_READ
		if perm & ida_segment.SEGPERM_WRITE:
			flags |= ElfUtil.PF_WRITE
		if perm & ida_segment.SEGPERM_EXEC:
			flags |= ElfUtil.PF_EXEC
		return flags

	def _match_phdr_boundaries_with_seg(self, idx, phdr, seg, exact):
		p_type, seg_flags = ElfUtil.phdr_type(phdr), ElfUtil.phdr_flags_from_perm(seg.perm)
		va_start, va_end = phdr['p_vaddr'], phdr['p_vaddr'] + phdr['p_memsz']

		info_str = 'type=0x%x(%s), flags=0x%x(%s), offset=0x%x, va_start=0x%x, va_end=0x%x, filesz=0x%x, memsz=0x%x' % (
			p_type, ElfUtil.stringify_phdr_type(p_type),
			phdr['p_flags'], ElfUtil.stringify_phdr_flags(phdr['p_flags']),
			phdr['p_offset'],
			va_start, va_end,
			phdr['p_filesz'], phdr['p_memsz']
		)

		if p_type not in [ElfUtil.PT_LOAD, ElfUtil.PT_DYNAMIC, ElfUtil.PT_SCE_PROCPARAM, ElfUtil.PT_SCE_MODULE_PARAM, ElfUtil.PT_GNU_EH_FRAME, ElfUtil.PT_TLS]:
			#print('Skipping phdr #%03d (%s): type mismatch (0x%x)' % (idx, info_str, p_type))
			return False

		if seg_flags != phdr['p_flags']:
			#print('Skipping phdr #%03d (%s): flags mismatch (segment: 0x%x, phdr: 0x%x)' % (idx, info_str, seg_flags, phdr['p_flags']))
			return False

		result = (va_start == seg.start_ea and va_end == seg.end_ea) if exact else ((va_start <= seg.start_ea < va_end) and (va_start < seg.end_ea <= va_end))
		if not result:
			#print('Skipping phdr #%03d (%s): %s addresses mismatch' % (idx, info_str, 'exact' if exact else 'inexact'))
			return False

		#print('Matched phdr #%03d (%s).' % (idx, info_str))

		return True

	def _parse_ehdr(self):
		data = self.elf_node.valobj()
		self.ehdr = parse_struct('Elf64_Ehdr', data)

	def _parse_phdrs(self):
		self.phdrs = []

		i = 0
		while self.elf_node.supval(i, ElfUtil.ELF_PHT_TAG) is not None:
			data = self.elf_node.supval(i, ElfUtil.ELF_PHT_TAG)
			phdr = parse_struct('Elf64_Phdr', data)
			self.phdrs.append(phdr)
			i += 1

	def _parse_shdrs(self):
		self.shdrs = []

		i = 0
		while self.elf_node.supval(i, ElfUtil.ELF_SHT_TAG) is not None:
			data = self.elf_node.supval(i, ElfUtil.ELF_SHT_TAG)
			shdr = parse_struct('Elf64_Shdr', data)
			self.shdrs.append(shdr)
			i += 1

for key in dir(ElfUtil):
	if not key.startswith('DT_') or key in ['DT_LOOS', 'DT_HIOS']:
		continue

	int_value = getattr(ElfUtil, key)
	if int_value >= ElfUtil.DT_LOOS and int_value <= ElfUtil.DT_HIOS:
		str_value = '%s(DT_LOOS+0x%x)' % (key, int_value - ElfUtil.DT_LOOS)
	else:
		str_value = '%s(0x%x)' % (key, int_value)

	ElfUtil._DT_STR_MAP[int_value] = str_value

class ElfTable(object):
	def __init__(self, ea=ida_idaapi.BADADDR, size=ida_idaapi.BADADDR, entry_size=ida_idaapi.BADADDR, entry_count=ida_idaapi.BADADDR):
		self.ea = ea
		self.size = size
		self.entry_size = entry_size
		self.entry_count = entry_count

	def type_name(self):
		return self.__class__.__name__

	def struct_name(self):
		return None

	def is_loaded(self):
		return self.ea != ida_idaapi.BADADDR and self.size != ida_idaapi.BADADDR

	def is_table_loaded(self):
		return self.is_loaded() and self.entry_size != ida_idaapi.BADADDR

	def get_entry(self, idx):
		assert self.is_table_loaded()
		assert self.struct_name() is not None

		count = self.get_num_entries()
		assert idx >= 0 and idx < count

		data = ida_bytes.get_bytes(self.ea + idx * self.entry_size, self.entry_size)
		assert len(data) == self.entry_size

		entry = parse_struct(self.struct_name(), data)

		return entry

	def get_num_entries(self):
		# XXX: We do not rely on entry count because it could be not set or may a wrong value.
		return self.size // self.entry_size

	def __repr__(self):
		params = []

		if self.ea != ida_idaapi.BADADDR:
			params.append('ea=0x%x' % self.ea)
		if self.size != ida_idaapi.BADADDR:
			params.append('size=0x%x' % self.size)
		if self.entry_size != ida_idaapi.BADADDR:
			params.append('entry_size=0x%x' % self.entry_size)
			params.append('real_entry_count=%d' % self.get_num_entries())
		if self.entry_count != ida_idaapi.BADADDR:
			params.append('entry_count=%d' % self.entry_count)

		return '%s(%s)' % (self.type_name(), ', '.join(params))

class RelaRelocTable(ElfTable):
	R_AMD64_NONE = 0
	R_AMD64_64 = 1
	R_AMD64_PC32 = 2
	R_AMD64_GOT32 = 3
	R_AMD64_PLT32 = 4
	R_AMD64_COPY = 5
	R_AMD64_GLOB_DAT = 6
	R_AMD64_JUMP_SLOT = 7
	R_AMD64_RELATIVE = 8
	R_AMD64_GOTPCREL = 9
	R_AMD64_32 = 10
	R_AMD64_32S = 11
	R_AMD64_16 = 12
	R_AMD64_PC16 = 13
	R_AMD64_8 = 14
	R_AMD64_PC8 = 15
	R_AMD64_DTPMOD64 = 16
	R_AMD64_DTPOFF64 = 17
	R_AMD64_TPOFF64 = 18
	R_AMD64_TLSGD = 19
	R_AMD64_TLSLD = 20
	R_AMD64_DTPOFF32 = 21
	R_AMD64_GOTTPOFF = 22
	R_AMD64_TPOFF32 = 23
	R_AMD64_PC64 = 24
	R_AMD64_GOTOFF64 = 25
	R_AMD64_GOTPC32 = 26

	class Record(object):
		def __init__(self, entry):
			self.entry = entry

		def get_symbol_idx(self):
			return as_uint64(self.entry['r_info']) >> 32

		def get_type(self):
			return as_uint32(self.entry['r_info'])

		def __repr__(self):
			params = []

			if self.entry is not None:
				params.append('entry=%s' % repr(self.entry))

			return 'Record(%s)' % ', '.join(params)

	def type_name(self):
		return 'ELF RELA Relocation Table'

	def struct_name(self):
		return 'Elf64_Rela'

class JmpRelRelocTable(RelaRelocTable):
	def type_name(self):
		return 'ELF JMPREL Relocation Table'

class SymbolTable(ElfTable):
	STB_LOCAL = 0
	STB_GLOBAL = 1
	STB_WEAK = 2

	STT_NOTYPE = 0
	STT_OBJECT = 1
	STT_FUNC = 2
	STT_SECTION = 3
	STT_FILE = 4
	STT_COMMON = 5
	STT_TLS = 6

	SHN_UNDEF = 0

	@staticmethod
	def sanitize_name(name):
		return re.sub(r'[^a-zA-Z0-9_]', '_', name)

	class Symbol(object):
		def __init__(self, entry):
			self.entry = entry
			self.module_name = None
			self.library_name = None
			self.symbol_name = None
			self.is_export = None

		def set_descriptor(self, module_name, library_name, symbol_name, is_export):
			self.module_name = module_name
			self.library_name = library_name
			self.symbol_name = symbol_name
			self.is_export = is_export

		def has_descriptor(self):
			return self.module_name is not None and self.library_name is not None and self.symbol_name is not None

		def get_binding(self):
			return as_uint8(self.entry['st_info']) >> 4

		def get_type(self):
			return as_uint8(self.entry['st_info']) & 0xF

		def _get_name(self, kind='simple'):
			module_name = SymbolTable.sanitize_name(self.module_name)
			library_name = SymbolTable.sanitize_name(self.library_name)

			if self.is_func(): suffix = 'f'
			elif self.is_object(): suffix = 'o'
			else: suffix = 'u'

			if isinstance(self.symbol_name, str):
				if kind == 'extended':
					symbol_name = SymbolTable.sanitize_name(self.symbol_name)
					if module_name != library_name:
						symbol_name = '%s_%s_%s' % (module_name, library_name, symbol_name)
					else:
						symbol_name = '%s_%s' % (module_name, symbol_name)
				elif kind == 'comment':
					symbol_name = self.symbol_name
					demangled_name = ida_name.demangle_name(symbol_name, idc.get_inf_attr(idc.INF_LONG_DEMNAMES))
					if demangled_name is not None:
						demangled_name = demangled_name.strip()
						if demangled_name:
							symbol_name = demangled_name
				else:
					symbol_name = self.symbol_name
			else:
				if module_name != library_name:
					symbol_name = 'nid%s_%s_%s_0x%016x' % (suffix, module_name, library_name, self.symbol_name)
				else:
					symbol_name = 'nid%s_%s_0x%016x' % (suffix, module_name, self.symbol_name)

			return symbol_name

		def get_name(self):
			return self._get_name('simple')

		def get_name_ex(self):
			return self._get_name('extended')

		def get_name_comment(self):
			name = self._get_name('comment')

			if self.is_func():
				type_str = 'Function'
			elif self.is_object():
				type_str = 'Object'
			else:
				type_str = 'Unknown'

			return '\n'.join([
				'%s:' % type_str,
				'  Module: %s' % self.module_name,
				'  Library: %s' % self.library_name,
				'  Name: %s' % name
			])

		def is_local(self):
			return self.get_binding() & SymbolTable.STB_LOCAL

		def is_global(self):
			return self.get_binding() & SymbolTable.STB_GLOBAL

		def is_weak(self):
			return self.get_binding() & SymbolTable.STB_WEAK

		def is_object(self): # Variable, array, etc.
			return self.get_type() == SymbolTable.STT_OBJECT

		def is_func(self): # Method or function.
			return self.get_type() == SymbolTable.STT_FUNC

		def is_tls(self): # TLS stuff
			return self.get_type() == SymbolTable.STT_TLS

		def __repr__(self):
			params = []

			if self.module_name is not None:
				params.append('module_name=%s' % self.module_name)
			if self.library_name is not None:
				params.append('library_name=%s' % self.library_name)
			if self.symbol_name is not None:
				if isinstance(self.symbol_name, str):
					params.append('symbol_name=%s' % self.symbol_name)
				else:
					params.append('symbol_nid=%s' % hex(self.symbol_name))
			if self.is_export is not None:
				params.append('is_export=%d' % self.is_export)

			if self.entry is not None:
				params.append('entry=%s' % repr(self.entry))

			return 'Symbol(%s)' % ', '.join(params)

	def type_name(self):
		return 'ELF Symbol Table'

	def struct_name(self):
		return 'Elf64_Sym'

class StringTable(ElfTable):
	def type_name(self):
		return 'ELF String Table'

	def get_string(self, offset):
		assert self.is_loaded()

		assert offset >= 0 and offset < self.size

		return read_cstring_at(self.ea + offset)

class HashTable(ElfTable):
	def type_name(self):
		return 'ELF Hash Table'

class IdTable(ElfTable):
	def type_name(self):
		return 'ELF ID Table'

class ps5_elf_plugin_t(ida_idaapi.plugin_t):
	flags = ida_idaapi.PLUGIN_PROC
	wanted_name = 'PS5 elf plugin'
	comment = f'{wanted_name} to extend loader functionality'
	wanted_hotkey = ''
	help = ''

	# Inhibit flags for symbol names.
	DEMANGLED_FORM = 0x0EA3FFE7 # MNG_SHORT_FORM | MNG_NOBASEDT | MNG_NOCALLC | MNG_NOCSVOL

	# Inhibit flags for type info comments.
	DEMANGLED_TYPEINFO = 0x06400007 # MNG_LONG_FORM

	# ud2 instruction bytes.
	UD2_INSN_BYTES = b'\x0F\x0B'

	# Netnode to determine if ELF is for Prospero.
	PROSPERO_NET_NODE = '$ prospero'

	class UiHooks(ida_kernwin.UI_Hooks):
		def __init__(self, plugin):
			super().__init__()

			self.plugin = plugin

		def ready_to_run(self, *args):
			# UI ready to run (called multiple times).
			return 0

		def database_inited(self, is_new_database, idc_script):
			# It is called multiple times, not really useful.
			return 0

		def plugin_loaded(self, plugin_info):
			#print('Loading plugin: %s' % plugin_info.name)
			return 0

	class IdbHooks(ida_idp.IDB_Hooks):
		def __init__(self, plugin):
			super().__init__()

			self.plugin = plugin

		def loader_finished(self, *args):
			# External file loader finished its work.
			# Use this event to augment the existing loader functionality.
			return 0

		def determined_main(self, ea):
			return 0

		def segm_added(self, seg):
			return 0

		def auto_empty_finally(self, *args):
			self.plugin.post_initial_analysis()
			return 0

	class IdpHooks(ida_idp.IDP_Hooks):
		def __init__(self, plugin):
			super().__init__()

			self.plugin = plugin

		def ev_func_bounds(self, possible_ret_code, func, max_func_end_ea):
			self.plugin.fixup_func_bounds(func, max_func_end_ea)
			return 0

	def __init__(self):
		super().__init__()

		self.elf = None
		self.file_type = None
		self.lib_versions = None
		self.prodg_meta_data = None
		self.soname = None
		self.orig_file_path = None
		self.needed_modules = None
		self.modules = None
		self.libraries = None
		self.relocation_type = None
		self.rela_reloc_table = None
		self.jmprel_reloc_table = None
		self.symbol_table = None
		self.string_table = None
		self.hash_table = None
		self.id_table = None
		self.got_start_ea = ida_idaapi.BADADDR
		self.got_plt_start_ea = ida_idaapi.BADADDR
		self.init_proc_ea = ida_idaapi.BADADDR
		self.term_proc_ea = ida_idaapi.BADADDR
		self.nids = None
		self.symbols = None

		self.ui_hooks = ps5_elf_plugin_t.UiHooks(self)
		self.idb_hooks = ps5_elf_plugin_t.IdbHooks(self)
		self.idp_hooks = ps5_elf_plugin_t.IdpHooks(self)

	def init(self):
		# Cannot be used in terminal mode.
		if not ida_kernwin.is_idaq():
			return ida_idaapi.PLUGIN_SKIP

		if not ida_hexrays.init_hexrays_plugin():
			return ida_idaapi.PLUGIN_SKIP

		print(f'Initializing plugin: {self.wanted_name}')

		file_path = ida_nalt.get_input_file_path()
		file_name = ida_nalt.get_root_filename()

		# Sanity check.
		if ida_ida.inf_get_filetype() != idc.FT_ELF or ida_ida.inf_get_procname() != 'metapc' or ida_ida.inf_is_be() or not ida_ida.inf_is_64bit():
			return ida_idaapi.PLUGIN_SKIP

		# Load needed type info libraries and register standard types.
		idc.add_default_til('gnuunx64')

		standard_types = ['Elf64_Ehdr', 'Elf64_Phdr', 'Elf64_Shdr', 'Elf64_Nhdr', 'Elf64_Rel', 'Elf64_Rela', 'Elf64_Dyn', 'Elf64_Sym']
		for type_name in standard_types:
			idc.import_type(-1, type_name)

		# Read and parse ELF header.
		elf = ElfUtil()
		if elf.is_inited():
			ehdr = elf.ehdr
			is_just_loaded = False
		else:
			ehdr_struct_name = 'Elf64_Ehdr'
			ehdr_size = get_struct_size(ehdr_struct_name)

			phdr_struct_name = 'Elf64_Phdr'
			phdr_size = get_struct_size(phdr_struct_name)

			is_prospero_elf = False

			try:
				with open(file_path, 'rb') as f:
					data = f.read(ehdr_size)

					while True:
						if len(data) != ehdr_size:
							break
						ehdr = parse_struct(ehdr_struct_name, data)

						phdr_offset = ehdr['e_phoff']
						if phdr_offset <= 0:
							break
						f.seek(phdr_offset)

						data = f.read(phdr_size)
						if len(data) != phdr_size:
							break
						phdr = parse_struct(phdr_struct_name, data)
						phdr_type, phdr_flags = ElfUtil.phdr_type(phdr), phdr['p_flags']

						if phdr_type != ElfUtil.PT_LOAD or phdr_flags != ElfUtil.PF_EXEC:
							break

						is_prospero_elf = True
						break
			except Exception as e:
				#print('Got exception during header parsing attempt:', e)
				pass

			if not is_prospero_elf:
				return ida_idaapi.PLUGIN_SKIP
			else:
				node = ida_netnode.netnode()
				node.create(ps5_elf_plugin_t.PROSPERO_NET_NODE)

			is_just_loaded = True

		# Determine file type.
		file_type_str = {
			ElfUtil.ET_SCE_EXEC_ASLR: 'Executable',
			ElfUtil.ET_SCE_DYNAMIC: 'PRX',
		}.get(ehdr['e_type'], None)

		if file_type_str is None:
			return ida_idaapi.PLUGIN_SKIP

		self.file_type = ehdr['e_type']

		print('File type: %s' % file_type_str)

		# Reset members.
		self.lib_versions = {}
		self.prodg_meta_data = {}
		self.soname = None
		self.orig_file_path = None
		self.needed_modules = []
		self.modules = {}
		self.libraries = {}
		self.relocation_type = None
		self.rela_reloc_table = None
		self.jmprel_reloc_table = None
		self.symbol_table = None
		self.string_table = None
		self.hash_table = None
		self.id_table = None
		self.got_start_ea = ida_idaapi.BADADDR
		self.got_plt_start_ea = ida_idaapi.BADADDR
		self.init_proc_ea = ida_idaapi.BADADDR
		self.term_proc_ea = ida_idaapi.BADADDR

		# Load additional type info libraries.
		for name in ['prospero']:
			idc.add_default_til(name)

		# Load known NIDS.
		self.nids = load_known_nids('ps5_symbols.txt')

		self.symbols = []

		# Load additional modules.
		ida_idaapi.require('gcc_extab')

		# Set up analyzer on the first load.
		if is_just_loaded:
			self.setup_analysis()
		else:
			self.elf = elf

		self.ui_hooks.hook()
		self.idb_hooks.hook()
		self.idp_hooks.hook()

		return ida_idaapi.PLUGIN_KEEP

	def term(self):
		#print(f'Terminating plugin: {self.wanted_name}')

		self.idp_hooks.unhook()
		self.idb_hooks.unhook()
		self.ui_hooks.unhook()

	def setup_analysis(self):
		# Set up common parameters.
		ida_ida.inf_set_ostype(0x6) # BSD OS
		ida_ida.inf_set_demnames(ida_ida.DEMNAM_NAME | ida_ida.DEMNAM_GCC3) # use GCC mangling names

		# Set up compiler parameters.
		ida_ida.inf_set_cc_id(ida_typeinf.COMP_GNU)
		ida_ida.inf_set_cc_cm(ida_typeinf.CM_N64 | ida_typeinf.CM_M_NN | ida_typeinf.CM_CC_CDECL)
		ida_ida.inf_set_cc_size_b(1)
		ida_ida.inf_set_cc_size_s(2)
		ida_ida.inf_set_cc_size_i(4)
		ida_ida.inf_set_cc_size_e(4)
		ida_ida.inf_set_cc_size_l(8)
		ida_ida.inf_set_cc_size_l(8)
		ida_ida.inf_set_cc_size_ldbl(8)
		ida_ida.inf_set_cc_defalign(0)

		# Set up analysis parameters.
		ida_ida.inf_set_mark_code(False) # Do not find functions inside .data segments.
		ida_ida.inf_set_create_func_tails(False) # Don not create function tails.
		ida_ida.inf_set_noflow_to_data(True) # Control flow to data segment is ignored.
		ida_ida.inf_set_rename_jumpfunc(False) # Rename jump functions as J_.

	def _fixup_segment(self, seg):
		image_base = ida_nalt.get_imagebase()

		name = ida_segment.get_segm_name(seg)
		type_id = ida_segment.segtype(seg.start_ea)

		print('Fixing up segment at 0x%x (type: %d, perm: 0x%x).' % (seg.start_ea, type_id, seg.perm))

		if type_id == ida_segment.SEG_CODE:
			other_seg = ida_segment.get_segm_by_name('.text')
			if seg.start_ea == image_base and seg.perm == ida_segment.SEGPERM_EXEC and not other_seg:
				ida_segment.set_segm_name(seg, '.text')
				print('Found .text segment.')
				return True
		elif type_id == ida_segment.SEG_DATA:
			other_seg = ida_segment.get_segm_by_name('.rodata')
			if seg.perm == ida_segment.SEGPERM_READ:
				if not other_seg:
					ida_segment.set_segm_name(seg, '.rodata')
					print('Found .rodata segment.')
					return True
				else:
					if name.lower().strip() == 'note':
						print('Deleting note segment.')
						ida_segment.del_segm(seg.start_ea, ida_segment.SEGMOD_KILL | ida_segment.SEGMOD_SILENT)
						return True
			elif seg.perm == ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE:
				# There are multiple R/W segments and we need more info to recognize them, so skip now and process them later.
				return False
			elif seg.perm == 0:
				other_seg = ida_segment.get_segm_by_name('.dynsym')
				if not other_seg:
					ida_segment.set_segm_name(seg, '.dynsym')
					print('Found .dynsym segment.')
					return True
		elif type_id == ida_segment.SEG_XTRN:
			other_seg = ida_segment.get_segm_by_name('extern')
			if seg.perm == 0 and not other_seg:
				ida_segment.set_segm_name(seg, 'extern')
				print('Found extern segment.')
				return True

		return False

	def _parse_extra_segments(self):
		assert self.elf.is_inited()

		file_path = ida_nalt.get_input_file_path()

		result = False

		dynamic_phdr = self.elf.find_phdr_by_type(ElfUtil.PT_DYNAMIC)

		if dynamic_phdr is not None:
			result |= self._parse_dynamic_segment(dynamic_phdr)

		comment_phdr = self.elf.find_phdr_by_type(ElfUtil.PT_SCE_COMMENT)
		version_phdr = self.elf.find_phdr_by_type(ElfUtil.PT_SCE_VERSION)

		if not comment_phdr and not version_phdr:
			return False

		with open(file_path, 'rb') as f:
			if comment_phdr is not None:
				f.seek(comment_phdr['p_offset'])
				comment_data = f.read(comment_phdr['p_filesz'])
				if len(comment_data) != comment_phdr['p_filesz']:
					comment_data = None
			else:
				comment_data = None

			if version_phdr is not None:
				f.seek(version_phdr['p_offset'])
				version_data = f.read(version_phdr['p_filesz'])
				if len(version_data) != version_phdr['p_filesz']:
					version_data = None
			else:
				version_data = None

		if comment_data:
			result |= self._parse_comment_segment(comment_data)
		if version_data:
			result |= self._parse_version_segment(version_data)

		return result

	def _parse_dynamic_segment(self, dynamic_phdr):
		print('Processing dynamic segment.')

		struct_name = 'Elf64_Dyn'
		struct_size = get_struct_size(struct_name)

		seg = ida_segment.get_segm_by_name('.dynsym')
		if not seg:
			ida_kernwin.warning('Unable to find .dynsym segment, cannot parse dynamic segment.')
			return False
		dynsym_base_ea = seg.start_ea

		ea = dynamic_phdr['p_vaddr']
		end_ea = dynamic_phdr['p_vaddr'] + dynamic_phdr['p_memsz']

		dyns = []
		while ea < end_ea:
			data = ida_bytes.get_bytes(ea, struct_size)
			if len(data) != struct_size:
				raise RuntimeError('Insufficient data of %s structure: 0x%x (expected: 0x%x)' % (struct_name, len(data), struct_size))

			dyn = parse_struct(struct_name, data)
			if dyn['d_tag'] == ElfUtil.DT_NULL:
				break
			dyns.append(dyn)

			ea += struct_size

		if not dyns:
			print('No dynamic tags found.')
			return True

		self.rela_reloc_table = RelaRelocTable()
		self.jmprel_reloc_table = JmpRelRelocTable()
		self.symbol_table = SymbolTable()
		self.string_table = StringTable()
		self.hash_table = HashTable()
		self.id_table = IdTable()

		print('Dynamic tags:')
		for dyn in dyns:
			tag, value = dyn['d_tag'], dyn['d_un']
			print('  %s: 0x%x' % (ElfUtil.stringify_dyn_tag(tag), value))

			if tag == ElfUtil.DT_NEEDED:
				name = read_cstring_at(dynsym_base_ea + value)
				self.needed_modules.append(name)
			elif tag == ElfUtil.DT_SONAME:
				self.soname = read_cstring_at(dynsym_base_ea + value)
			elif tag in [ElfUtil.DT_SCE_NEEDED_MODULE, ElfUtil.DT_SCE_NEEDED_MODULE_PPR]:
				module_id = ObjectInfo.obj_id(value)
				if module_id not in self.modules:
					self.modules[module_id] = ObjectInfo()
				self.modules[module_id].set_info(value)
				self.modules[module_id].update_name(dynsym_base_ea)
			elif tag in [ElfUtil.DT_SCE_EXPORT_LIB, ElfUtil.DT_SCE_EXPORT_LIB_PPR]:
				library_id = ObjectInfo.obj_id(value)
				if library_id not in self.libraries:
					self.libraries[library_id] = ObjectInfo()
				self.libraries[library_id].set_info(value, True)
				self.libraries[library_id].update_name(dynsym_base_ea)
			elif tag == ElfUtil.DT_SCE_IMPORT_LIB_ATTR:
				library_id = ObjectInfo.obj_id(value)
				if library_id not in self.libraries:
					self.libraries[library_id] = ObjectInfo()
				self.libraries[library_id].set_attr(value)
			elif tag in [ElfUtil.DT_SCE_MODULE_INFO, ElfUtil.DT_SCE_MODULE_INFO_PPR]:
				module_id = ObjectInfo.obj_id(value)
				if module_id not in self.modules:
					self.modules[module_id] = ObjectInfo()
				self.modules[module_id].set_info(value, True)
				self.modules[module_id].update_name(dynsym_base_ea)
			elif tag == ElfUtil.DT_SCE_MODULE_ATTR:
				module_id = ObjectInfo.obj_id(value)
				if module_id not in self.modules:
					self.modules[module_id] = ObjectInfo()
				self.modules[module_id].set_attr(value)
			elif tag in [ElfUtil.DT_SCE_ORIGINAL_FILENAME, ElfUtil.DT_SCE_ORIGINAL_FILENAME_PPR]:
				self.orig_file_path = read_cstring_at(dynsym_base_ea + value)
			elif tag in [ElfUtil.DT_SCE_IMPORT_LIB, ElfUtil.DT_SCE_IMPORT_LIB_PPR]:
				library_id = ObjectInfo.obj_id(value)
				if library_id not in self.libraries:
					self.libraries[library_id] = ObjectInfo()
				self.libraries[library_id].set_info(value)
				self.libraries[library_id].update_name(dynsym_base_ea)
			elif tag == ElfUtil.DT_SCE_EXPORT_LIB_ATTR:
				library_id = ObjectInfo.obj_id(value)
				if library_id not in self.libraries:
					self.libraries[library_id] = ObjectInfo()
				self.libraries[library_id].set_attr(value)
			elif tag == ElfUtil.DT_RELA: # ELF RELA Relocation Table
				ea = as_uint64(value)
				if ea != 0 and ea != ida_idaapi.BADADDR:
					self.rela_reloc_table.ea = ea
			elif tag == ElfUtil.DT_RELASZ: # ELF RELA Relocation Table
				size = as_uint64(value)
				if size != ida_idaapi.BADADDR:
					self.rela_reloc_table.size = size
			elif tag == ElfUtil.DT_RELAENT: # ELF RELA Relocation Table
				size = as_uint64(value)
				if size != ida_idaapi.BADADDR:
					assert size == get_struct_size(self.rela_reloc_table.struct_name())
					self.rela_reloc_table.entry_size = size
			elif tag == ElfUtil.DT_RELACOUNT: # ELF RELA Relocation Table
				count = as_uint64(value)
				if count != ida_idaapi.BADADDR:
					# TODO: Why is it smaller than actual count?
					self.rela_reloc_table.entry_count = count
			elif tag == ElfUtil.DT_JMPREL: # ELF JMPREL Relocation Table
				ea = as_uint64(value)
				if ea != 0 and ea != ida_idaapi.BADADDR:
					self.jmprel_reloc_table.ea = ea
			elif tag == ElfUtil.DT_PLTRELSZ: # ELF JMPREL Relocation Table
				size = as_uint64(value)
				if size != ida_idaapi.BADADDR:
					self.jmprel_reloc_table.size = size
			elif tag == ElfUtil.DT_PLTGOT:
				ea = as_uint64(value)
				if ea != 0 and ea != ida_idaapi.BADADDR:
					self.got_plt_start_ea = ea
			elif tag == ElfUtil.DT_PLTREL:
				self.relocation_type = as_uint32(value)
				if self.relocation_type != ElfUtil.DT_REL and self.relocation_type != ElfUtil.DT_RELA:
					ida_kernwin.warning('Unsupported PLT relocation type: 0x%x' % self.relocation_type)
			elif tag == ElfUtil.DT_SYMTAB: # ELF Symbol Table
				ea = as_uint64(value)
				if ea != 0 and ea != ida_idaapi.BADADDR:
					self.symbol_table.ea = ea
			elif tag == ElfUtil.DT_SCE_SYMTABSZ: # ELF Symbol Table
				size = as_uint64(value)
				if size != ida_idaapi.BADADDR:
					self.symbol_table.size = size
			elif tag == ElfUtil.DT_SYMENT: # ELF Symbol Table
				size = as_uint64(value)
				if size != ida_idaapi.BADADDR:
					assert size == get_struct_size(self.symbol_table.struct_name())
					self.symbol_table.entry_size = size
			elif tag == ElfUtil.DT_STRTAB: # ELF String Table
				ea = as_uint64(value)
				if ea != 0 and ea != ida_idaapi.BADADDR:
					self.string_table.ea = ea
			elif tag == ElfUtil.DT_STRSZ: # ELF String Table
				size = as_uint64(value)
				if size != ida_idaapi.BADADDR:
					self.string_table.size = size
			elif tag == ElfUtil.DT_HASH: # ELF Hash Table
				ea = as_uint64(value)
				if ea != 0 and ea != ida_idaapi.BADADDR:
					self.hash_table.ea = ea
			elif tag == ElfUtil.DT_SCE_HASHSZ: # ELF Hash Table
				size = as_uint64(value)
				if size != ida_idaapi.BADADDR:
					self.hash_table.size = size
			elif tag == ElfUtil.DT_SCE_IDTABENTSZ: # ELF ID Table
				# TODO: Where are ea/size tags?
				size = as_uint64(value)
				if size != ida_idaapi.BADADDR:
					# TODO: assert size == get_struct_size(self.id_table.struct_name())
					self.id_table.entry_size = size
			elif tag == ElfUtil.DT_INIT:
				self.init_proc_ea = value
			elif tag == ElfUtil.DT_FINI:
				self.term_proc_ea = value
			elif tag == ElfUtil.DT_PREINIT_ARRAY:
				# TODO
				continue
			elif tag == ElfUtil.DT_PREINIT_ARRAYSZ:
				# TODO
				continue
			elif tag == ElfUtil.DT_INIT_ARRAY:
				# TODO
				continue
			elif tag == ElfUtil.DT_INIT_ARRAYSZ:
				# TODO
				continue
			elif tag == ElfUtil.DT_FINI_ARRAY:
				# TODO
				continue
			elif tag == ElfUtil.DT_FINI_ARRAYSZ:
				# TODO
				continue

		if self.jmprel_reloc_table.entry_size == ida_idaapi.BADADDR:
			self.jmprel_reloc_table.entry_size = get_struct_size(self.jmprel_reloc_table.struct_name())

		if self.rela_reloc_table.entry_size == ida_idaapi.BADADDR:
			self.rela_reloc_table.entry_size = get_struct_size(self.rela_reloc_table.struct_name())

		if self.id_table.entry_size != ida_idaapi.BADADDR and self.id_table.entry_size != 0x8:
			ida_kernwin.warning('Unsupported ID table entry size: 0x%x' % self.id_table.entry_size)

		return True

	def _parse_comment_segment(self, data):
		print('Processing comment segment.')

		f = BytesIO(data)

		while True:
			key = f.read(struct.calcsize('4s'))
			if len(key) < struct.calcsize('4s'):
				# Reached end of file.
				break
			key = key.rstrip(b'\0').decode('ascii')

			data = f.read(struct.calcsize('2I'))
			if len(data) != struct.calcsize('2I'):
				ida_kernwin.warning('Truncated data at comment segment.')
				return False

			max_length, length = struct.unpack('<2I', data)
			value = f.read(length)

			if len(value) != length:
				ida_kernwin.warning('Truncated data at comment segment.')
				return False

			# Try to decode value as UTF-8 string.
			try:
				value = value.decode('utf-8').rstrip('\0')
			except:
				pass

			self.prodg_meta_data[key] = value

		params = {
			'PATH': 'Original path',
		}

		for key, desc in params.items():
			if key not in self.prodg_meta_data:
				continue
			print('%s: %s' % (desc, self.prodg_meta_data[key]))

		return True

	def _parse_version_segment(self, data):
		print('Processing version segment.')

		f = BytesIO(data)

		while True:
			data = f.read(struct.calcsize('2H'))
			if data == b'':
				# Reached end of file.
				break
			elif len(data) != struct.calcsize('2H'):
				ida_kernwin.warning('Truncated data at version segment.')
				return False

			reserved, length = struct.unpack('<2H', data)
			assert reserved == 0
			if length == 0:
				continue

			data = f.read(length)
			if len(data) != length:
				ida_kernwin.warning('Truncated data at version segment.')
				return False

			type_id, data = data[0], data[1:]
			if type_id == 0x8:
				name, version = data.split(b':')
				name = name.decode('ascii')
				version = version.hex().upper() # TODO: Need to parse version properly.
				print('Library %s version: %s' % (name, version))
				self.lib_versions[name] = version
			else:
				ida_kernwin.warning('Unknown type id 0x%x in version info.' % type_id)
				continue

		return True

	def _fixup_padding_segment(self):
		seg = ida_segment.get_segm_by_name('.sce_padding')
		if not seg:
			image_base = ida_nalt.get_imagebase()

			has_padding = ida_bytes.get_bytes(image_base, ElfUtil.SCE_PADDING_SIZE) == ElfUtil.SCE_PADDING
			if not has_padding:
				return False

			text_seg = ida_segment.get_segm_by_name('.text')
			if not text_seg:
				ida_kernwin.warning('Unable to find .text segment, cannot fixup .sce_padding segment.')
				return False

			if text_seg.start_ea == image_base:
				print('Moving start of .text segment from 0x%x to 0x%x.' % (text_seg.start_ea, text_seg.start_ea + ElfUtil.SCE_PADDING_SIZE))
				ida_segment.set_segm_start(text_seg.start_ea, text_seg.start_ea + ElfUtil.SCE_PADDING_SIZE, ida_segment.SEGMOD_KILL | ida_segment.SEGMOD_SILENT)

			print('Creating .sce_padding segment.')
			seg = ida_segment.segment_t()
			seg.start_ea = image_base
			seg.end_ea = image_base + ElfUtil.SCE_PADDING_SIZE
			seg.bitness = text_seg.bitness
			seg.type = ida_segment.SEG_UNDF
			seg.perm = 0
			ida_segment.add_segm_ex(seg, '.sce_padding', None, ida_segment.ADDSEG_NOAA)

		seg = ida_segment.get_segm_by_name('.sce_padding')
		if not seg:
			return False

		ida_auto.auto_mark_range(seg.start_ea, seg.end_ea, ida_auto.AU_UNK)
		ida_bytes.del_items(seg.start_ea, ida_bytes.DELIT_SIMPLE, ElfUtil.SCE_PADDING_SIZE)

		print('Found .sce_padding segment.')

		return True

	def _link_segments_with_phdrs(self):
		num_segments = ida_segment.get_segm_qty()
		print('Number of segments: %d' % num_segments)

		for i in range(num_segments):
			seg = ida_segment.getnseg(i)
			if not seg:
				continue
			idx = ida_segment.get_segm_num(seg.start_ea)

			phdr = self.elf.find_phdr_by_seg(seg)
			if not phdr:
				continue

	def _fixup_segment_perms(self):
		print('Fixing up segments permissions.')

		seg, last_seg = ida_segment.get_first_seg(), ida_segment.get_last_seg()

		while seg:
			name = ida_segment.get_segm_name(seg)

			if name in ['.text', '.init', '.fini', '.plt'] or name.startswith('.text.'):
				seg.perm = ida_segment.SEGPERM_EXEC
				need_update = True
			else:
				need_update = False

			if not need_update:
				print('Updating %s segment permissions.' % name)
				ida_segment.update_segm(seg)

			seg = ida_segment.get_next_seg(seg.start_ea)
			if seg == last_seg:
				break

		return True

	def _fixup_init_fini_segments(self):
		print('Fixing up .init and .fini segments.')

		info = { '.init_proc': '.init', '.term_proc': '.fini' }
		segments = {}

		for func_name, segment_name in info.items():
			seg = ida_segment.get_segm_by_name(segment_name)
			if seg:
				continue

			ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_name)
			if ea == ida_idaapi.BADADDR:
				ida_kernwin.warning('Unable to find %s function address, cannot fixup %s segment.' % (func_name, segment_name))
				continue

			func = ida_funcs.get_func(ea)
			if not func:
				ida_kernwin.warning('Unable to find %s function, cannot fixup %s segment.' % (func_name, segment_name))
				continue
			start_ea, end_ea = func.start_ea, func.end_ea

			text_seg = ida_segment.get_segm_by_name('.text')
			if not text_seg:
				ida_kernwin.warning('Unable to find .text segment, cannot fixup %s segment.' % segment_name)
				continue

			if segment_name == '.init':
				end_ea = align_up(end_ea, 0x10)
				print('Moving start of .text segment from 0x%x to 0x%x.' % (text_seg.start_ea, end_ea))
				ida_segment.set_segm_start(text_seg.start_ea, end_ea, ida_segment.SEGMOD_KEEP | ida_segment.SEGMOD_SILENT)
			elif segment_name == '.fini':
				start_ea = align_up(start_ea, 0x10)
				print('Moving end of .text segment from 0x%x to 0x%x.' % (text_seg.end_ea, start_ea))
				ida_segment.set_segm_end(text_seg.start_ea, start_ea, ida_segment.SEGMOD_KEEP | ida_segment.SEGMOD_SILENT)

			seg = ida_segment.segment_t()
			seg.start_ea = start_ea
			seg.end_ea = end_ea
			seg.bitness = text_seg.bitness
			seg.type = text_seg.type
			seg.perm = text_seg.perm
			segments[segment_name] = seg

		text_seg = ida_segment.get_segm_by_name('.text')
		if not text_seg:
			ida_kernwin.warning('Unable to find .text segment, cannot fixup .init and .proc segments.')
			return False

		for segment_name, seg in segments.items():
			print('Creating %s segment.' % segment_name)
			ida_segment.add_segm_ex(seg, segment_name, ida_segment.get_segm_class(text_seg), ida_segment.ADDSEG_NOSREG)

		return True

	def _fixup_eh_segments(self):
		assert self.elf.is_inited()

		print('Fixing up .eh_frame and .eh_frame_hdr segments.')

		seg = ida_segment.get_segm_by_name('.eh_frame')
		if seg:
			# Segment already exists, skipping it.
			return True

		seg = ida_segment.get_segm_by_name('.eh_frame_hdr')
		if not seg:
			seg = ida_segment.get_segm_by_name('.rodata')
			if not seg:
				ida_kernwin.warning('Unable to find .rodata segment, cannot fixup .eh_frame_hdr segment.')
				return False

			phdr = self.elf.find_phdr_by_type(ElfUtil.PT_GNU_EH_FRAME)
			if phdr is None:
				ida_kernwin.warning('Unable to find program header for segment .eh_frame_hdr, cannot fixup it.')
				return False

			new_seg = ida_segment.segment_t()
			new_seg.start_ea = phdr['p_vaddr']
			new_seg.end_ea = phdr['p_vaddr'] + phdr['p_memsz']
			new_seg.bitness = seg.bitness
			new_seg.type = seg.type
			new_seg.perm = seg.perm

			print('Creating .eh_frame_hdr segment.')
			ida_segment.add_segm_ex(new_seg, '.eh_frame_hdr', ida_segment.get_segm_class(seg), ida_segment.ADDSEG_NOSREG)

			seg = ida_segment.get_segm_by_name('.eh_frame_hdr')

		if not seg:
			ida_kernwin.warning('Unable to find .eh_frame_hdr segment, cannot fixup .eh_frame segment.')
			return False

		ea = seg.start_ea

		exc_data_base_ea, exc_version = ea, gcc_extab.format_byte(ea, 'version')
		ea += struct.calcsize('B')

		exc_eh_frame_ptr_enc, ea = gcc_extab.format_enc(ea, 'eh frame ptr encoding')
		exc_fde_count_enc, ea = gcc_extab.format_enc(ea, 'fde count encoding')
		exc_ent_table_enc, ea = gcc_extab.format_enc(ea, 'ent binary table encoding')
		exc_eh_frame_ptr, ea = gcc_extab.read_enc_val(ea, exc_eh_frame_ptr_enc, True, data_ea=exc_data_base_ea)

		if exc_eh_frame_ptr != ida_idaapi.BADADDR and exc_eh_frame_ptr < seg.start_ea:
			new_seg = ida_segment.segment_t()
			new_seg.start_ea = exc_eh_frame_ptr
			new_seg.end_ea = seg.start_ea
			new_seg.bitness = seg.bitness
			new_seg.type = seg.type
			new_seg.perm = seg.perm

			print('Creating .eh_frame segment.')
			ida_segment.add_segm_ex(new_seg, '.eh_frame', ida_segment.get_segm_class(seg), ida_segment.ADDSEG_NOSREG)

		return True

	def _fixup_param_segment(self):
		assert self.elf.is_inited()

		if self.file_type == ElfUtil.ET_SCE_EXEC_ASLR:
			phdr_type = ElfUtil.PT_SCE_PROCPARAM
			segment_name = '.sce_process_param'
			struct_name = 'sceProcessParam'
			handler_cb = self._fixup_process_param_segment
		else:
			phdr_type = ElfUtil.PT_SCE_MODULE_PARAM
			segment_name = '.sce_module_param'
			struct_name = 'sceModuleParam'
			handler_cb = self._fixup_module_param_segment

		phdr = self.elf.find_phdr_by_type(phdr_type)
		if phdr is None:
			ida_kernwin.warning('Unable to find program header for segment %s, cannot fixup it.' % segment_name)
			return False

		seg = ida_segment.get_segm_by_name(segment_name)
		if not seg:
			seg = ida_segment.get_segm_by_name('.rodata')
			if not seg:
				ida_kernwin.warning('Unable to find .rodata segment, cannot fixup %s segment.' % segment_name)
				return False

			new_seg = ida_segment.segment_t()
			new_seg.start_ea = phdr['p_vaddr']
			new_seg.end_ea = align_up(phdr['p_vaddr'] + phdr['p_memsz'], 0x10)

			new_seg.bitness = seg.bitness
			new_seg.type = seg.type
			new_seg.perm = seg.perm

			print('Creating %s segment.' % segment_name)
			ida_segment.add_segm_ex(new_seg, segment_name, ida_segment.get_segm_class(seg), ida_segment.ADDSEG_NOSREG)

			seg = ida_segment.get_segm_by_name(segment_name)

		if not seg:
			ida_kernwin.warning('Unable to find %s segment, cannot fixup it.' % segment_name)
			return False

		print('Processing %s segment.' % segment_name)

		size = ida_bytes.get_qword(seg.start_ea)
		if size == ida_idaapi.BADADDR or size < struct.calcsize('Q'):
			ida_kernwin.warning('Unexpected size of %s structure.' % struct_name)
			return False
		print('%s structure size: 0x%x' % (struct_name, size))

		end_ea = align_up(seg.start_ea + size, 0x10)
		if seg.end_ea != end_ea:
			print('Moving end of %s segment from 0x%x to 0x%x.' % (segment_name, seg.end_ea, end_ea))
			ida_segment.set_segm_end(seg.start_ea, end_ea, ida_segment.SEGMOD_KEEP | ida_segment.SEGMOD_SILENT)

		data = ida_bytes.get_bytes(seg.start_ea, size)
		if len(data) != size:
			raise RuntimeError('Insufficient data of %s structure: 0x%x (expected: 0x%x)' % (struct_name, len(data), size))

		return handler_cb(segment_name, struct_name, data[struct.calcsize('Q'):])

	def _fixup_process_param_segment(self, segment_name, struct_name, data):
		fmt = '<4s3I5Q'
		extra_fmt = '<3Q'
		data_size = len(data)
		expected_size = struct.calcsize(fmt)
		expected_extra_size = struct.calcsize(extra_fmt)
		if data_size < expected_size:
			raise RuntimeError('Unsupported size of %s structure: 0x%x (expected: 0x%x)' % (struct_name, data_size, expected_size))
		elif data_size > expected_size + expected_extra_size:
			ida_kernwin.warning('Size of %s structure is larger than expected: 0x%x (expected: 0x%x)' % (struct_name, data_size, expected_size + expected_extra_size))

		# TODO: Check these fields.
		magic, entry_count, sdk_version, unk1, process_name_ea, user_main_thread_name_ea, user_main_thread_priority_ea, user_main_thread_stack_size_ea, libc_param_ea = struct.unpack(fmt, data[:expected_size])
		if magic != ElfUtil.SCE_PROCESS_PARAM_MAGIC:
			raise RuntimeError('Invalid magic in %s structure: 0x%08x' % (struct_name, magic))
		offset = expected_size
		data_size -= offset

		# TODO: Check if it is really an address and not a value.
		kernel_mem_param_ea = ida_idaapi.BADADDR
		if data_size >= 0x8:
			kernel_mem_param_ea, = struct.unpack('<Q', data[offset:offset + struct.calcsize('Q')])
			offset += struct.calcsize('Q')
			data_size -= struct.calcsize('Q')

		# TODO: Check if it is really an address and not a value.
		kernel_fs_param_ea = ida_idaapi.BADADDR
		if data_size >= 0x8:
			kernel_fs_param_ea, = struct.unpack('<Q', data[offset:offset + struct.calcsize('Q')])
			offset += struct.calcsize('Q')
			data_size -= struct.calcsize('Q')

		# TODO: Check if it is really an address and not a value.
		process_preload_enabled_ea = ida_idaapi.BADADDR
		if data_size >= 0x8:
			process_preload_enabled_ea, = struct.unpack('<Q', data[offset:offset + struct.calcsize('Q')])
			offset += struct.calcsize('Q')
			data_size -= struct.calcsize('Q')

		# TODO: Create proper structure.
		print('Process info:')
		print('  Magic: 0x%s' % magic.hex())
		print('  Entry count: %d' % entry_count)
		print('  SDK version: 0x%x' % sdk_version)
		print('  Unk1: 0x%x' % unk1)
		print('  Process name ea: 0x%x' % process_name_ea)
		print('  User main thread ea: 0x%x' % user_main_thread_name_ea)
		print('  User main thread priority ea: 0x%x' % user_main_thread_priority_ea)
		print('  User main thread stack size ea: 0x%x' % user_main_thread_stack_size_ea)
		print('  Libc param ea: 0x%x' % libc_param_ea)
		if kernel_mem_param_ea != ida_idaapi.BADADDR:
			print('  Kernel mem param ea: 0x%x' % kernel_mem_param_ea)
		if kernel_fs_param_ea != ida_idaapi.BADADDR:
			print('  Kernel fs param ea: 0x%x' % kernel_fs_param_ea)
		if process_preload_enabled_ea != ida_idaapi.BADADDR:
			print('  Process preload enabled ea: 0x%x' % process_preload_enabled_ea)

		return True

	def _fixup_module_param_segment(self, segment_name, struct_name, data):
		fmt = '<4sIQ2I'
		data_size = len(data)
		expected_size = struct.calcsize(fmt)
		if data_size < expected_size:
			raise RuntimeError('Unsupported size of %s structure: 0x%x (expected: 0x%x)' % (struct_name, data_size, expected_size))
		elif data_size > expected_size:
			ida_kernwin.warning('Size of %s structure is larger than expected: 0x%x (expected: 0x%x)' % (struct_name, data_size, expected_size))

		# TODO: Check these fields.
		magic, entry_count, sdk_version, unk1, unk2 = struct.unpack(fmt, data[:expected_size])
		if magic != ElfUtil.SCE_MODULE_PARAM_MAGIC:
			raise RuntimeError('Invalid magic in %s structure: 0x%08x' % (struct_name, magic))

		# TODO: Create proper structure.
		print('Module info:')
		print('  Magic: 0x%s' % magic.hex())
		print('  Entry count: %d' % entry_count)
		print('  SDK version: 0x%x' % sdk_version)
		print('  Unk1: 0x%x' % unk1)
		print('  Unk2: 0x%x' % unk2)

		return True

	def _fixup_data_segment(self):
		seg = ida_segment.get_segm_by_name('.data')
		if seg:
			# Segment already exists, skipping it.
			return False

		seg = self._find_last_rw_seg()
		if not seg:
			ida_kernwin.warning('Unable to find R/W segment, cannot fixup .data segment.')
			return False

		seg_name = ida_segment.get_segm_name(seg)
		if seg_name.startswith('.'):
			ida_kernwin.warning('R/W segment starts with dot already, cannot fixup .data segment.')
			return False

		ida_segment.set_segm_name(seg, '.data')

		return True

	def _fixup_extra_segments(self):
		print('Fixing up extra .data segments.')

		first_seg, last_seg = ida_segment.get_first_seg(), ida_segment.get_last_seg()

		seg = first_seg
		while seg:
			name = ida_segment.get_segm_name(seg)
			sclass = ida_segment.get_segm_class(seg)
			idx = ida_segment.get_segm_num(seg.start_ea)

			if name.lower() == 'load' and not name.startswith('.') and sclass == 'DATA':
				print('Renaming extra R/W %s segment #%03d to .data.' % (name, idx))
				ida_segment.set_segm_name(seg, '.data')

			seg = ida_segment.get_next_seg(seg.start_ea)
			if seg == last_seg:
				break

		print('Merging similar neighboring segments.')

		seg1 = first_seg
		while seg1:
			name1 = ida_segment.get_segm_name(seg1)
			sclass1 = ida_segment.get_segm_class(seg1)
			idx1 = ida_segment.get_segm_num(seg1.start_ea)

			#print('Processing segment #%03d: %s' % (idx1, name1))

			finished = False
			while not finished:
				seg2 = ida_segment.get_next_seg(seg1.start_ea)
				if not seg2:
					finished = True
					break
				is_last = seg2 == last_seg

				name2 = ida_segment.get_segm_name(seg2)
				sclass2 = ida_segment.get_segm_class(seg2)
				idx2 = ida_segment.get_segm_num(seg2.start_ea)

				#print('Comparing with segment #%03d: %s' % (idx2, name2))

				if name1 != name2 or seg1.perm != seg2.perm or seg1.end_ea != seg2.start_ea:
					#print('Merging done: params mismatch')
					finished = True
					break

				print('Merging segments #%03d(%s) and #%03d(%s): [0x%x;0x%x) / [0x%x;0x%x)' % (idx1, name1, idx2, name2, seg1.start_ea, seg1.end_ea, seg2.start_ea, seg2.end_ea))

				end_ea = seg2.end_ea
				assert end_ea >= seg1.end_ea

				ida_segment.del_segm(seg2.start_ea, ida_segment.SEGMOD_KEEP)
				ida_segment.set_segm_end(seg1.start_ea, end_ea, ida_segment.SEGMOD_KEEP)
				ida_segment.update_segm(seg1)

				if is_last:
					#print('Merging done: was last segment')
					break

			seg1 = ida_segment.get_next_seg(seg1.start_ea)
			if seg1 == last_seg:
				break

		return True

	def _fixup_got_segments(self):
		print('Fixing up .got and .got.plt segments.')

		result = False

		if self.got_plt_start_ea != ida_idaapi.BADADDR:
			print('Address of .got.plt section: 0x%x' % self.got_plt_start_ea)

			seg = ida_segment.get_segm_by_name('.got.plt')
			if not seg:
				seg = ida_segment.getseg(self.got_plt_start_ea)
				if not seg:
					ida_kernwin.warning('Unable to find segment which includes .got.plt, cannot fixup .got.plt segment.')
					return False

				new_seg = ida_segment.segment_t()
				new_seg.start_ea = self.got_plt_start_ea
				new_seg.end_ea = seg.end_ea
				new_seg.bitness = seg.bitness
				new_seg.type = seg.type
				new_seg.perm = seg.perm

				print('Creating .got.plt segment.')
				ida_segment.add_segm_ex(new_seg, '.got.plt', ida_segment.get_segm_class(seg), 0)
			else:
				# Segment already exists, skipping it.
				pass

			result |= True

		if self.got_start_ea != ida_idaapi.BADADDR:
			print('Address of .got section: 0x%x' % self.got_start_ea)

			seg = ida_segment.get_segm_by_name('.got')
			if not seg:
				seg = ida_segment.getseg(self.got_start_ea)
				if not seg:
					ida_kernwin.warning('Unable to find segment which includes .got, cannot fixup .got segment.')
					return False

				new_seg = ida_segment.segment_t()
				new_seg.start_ea = self.got_start_ea
				new_seg.end_ea = seg.end_ea
				new_seg.bitness = seg.bitness
				new_seg.type = seg.type
				new_seg.perm = seg.perm

				print('Creating .got segment.')
				ida_segment.add_segm_ex(new_seg, '.got', ida_segment.get_segm_class(seg), 0)
			else:
				# Segment already exists, skipping it.
				pass

			result |= True

		return result

	def _fixup_ctors_dtors_segments(self):
		print('Fixing up .ctors and .dtors segments.')

		# The linker must build two lists of these functions - a list of initialization functions, called __CTOR_LIST__, and a list of termination functions, called __DTOR_LIST__.
		#
		# Each list always begins with an ignored function pointer (which may hold 0, -1, or a count of the function pointers after it, depending on the environment).
		# This is followed by a series of zero or more function pointers to constructors (or destructors), followed by a function pointer containing zero.

		data_seg = ida_segment.get_segm_by_name('.data')
		if not data_seg:
			ida_kernwin.warning('Unable to find .data segment, cannot fixup .ctors and .dtors segments.')
			return False
		seg_class, seg_bitness, seg_type, seg_perm = ida_segment.get_segm_class(data_seg), data_seg.bitness, data_seg.type, data_seg.perm

		ea_pair = self._fixup_dtors_segment()
		if not ea_pair:
			return False
		dtors_start_ea, dtors_end_ea = ea_pair

		if dtors_start_ea != ida_idaapi.BADADDR and dtors_end_ea != ida_idaapi.BADADDR:
			seg = ida_segment.segment_t()
			seg.start_ea = dtors_start_ea
			seg.end_ea = dtors_end_ea
			seg.bitness = seg_bitness
			seg.type = seg_type
			seg.perm = seg_perm

			print('Creating .dtors segment.')
			ida_segment.add_segm_ex(seg, '.dtors', seg_class, 0)
		else:
			ida_kernwin.warning('Unable to find .dtors segment.')

		ea_pair = self._fixup_ctors_segment()
		if not ea_pair:
			return False
		ctors_start_ea, ctors_end_ea = ea_pair

		if ctors_start_ea != ida_idaapi.BADADDR and ctors_end_ea != ida_idaapi.BADADDR:
			seg = ida_segment.segment_t()
			seg.start_ea = ctors_start_ea
			seg.end_ea = ctors_end_ea
			seg.bitness = seg_bitness
			seg.type = seg_type
			seg.perm = seg_perm

			print('Creating .ctors segment.')
			ida_segment.add_segm_ex(seg, '.ctors', seg_class, 0)
		else:
			ida_kernwin.warning('Unable to find .ctors segment.')

		return True

	def _fixup_ctors_segment(self):
		# static func_ptr __CTOR_LIST__[1] = { (func_ptr) (-1) };
		# ...
		# static func_ptr __CTOR_END__[1] = { (func_ptr) 0 };
		#
		# static void __do_global_ctors_aux()
		# {
		#   func_ptr* p;
		#   for (p = __CTOR_END__ - 1; *p != (func_ptr)-1; --p)
		#     (*p)();
		# }

		dtors_seg = ida_segment.get_segm_by_name('.dtors')
		if not dtors_seg:
			ida_kernwin.warning('Unable to find .dtors segment, cannot fixup .ctors segment.')
			return None
		dtors_start_ea, dtors_end_ea = dtors_seg.start_ea, dtors_seg.end_ea
		if dtors_start_ea == ida_idaapi.BADADDR or dtors_end_ea == ida_idaapi.BADADDR:
			ida_kernwin.warning('Unexpected .dtors segment addresses, cannot fixup .ctors segment.')
			return None

		ea = ida_name.get_name_ea(ida_idaapi.BADADDR, '.init_proc')
		if ea == ida_idaapi.BADADDR:
			ida_kernwin.warning('Unable to find .init_proc, cannot fixup .ctors segment.')
			return None

		preinit_array_end_ea = ida_idaapi.BADADDR
		got_plt_end_ea = ida_idaapi.BADADDR
		cmp_found = mov_found = lea_found = False
		mov_reg = None
		for ea in idautils.FuncItems(ea):
			if not cmp_found and check_insn_format(ea, 'cmp', [(ida_ua.o_reg, None), (ida_ua.o_mem, None)]):
				value = idc.get_operand_value(ea, 1)
				if value != ida_idaapi.BADADDR and preinit_array_end_ea == ida_idaapi.BADADDR:
					preinit_array_end_ea = value
				cmp_found = True
			elif not mov_found and check_insn_format(ea, 'mov', [(ida_ua.o_reg, None), (ida_ua.o_phrase, None)]):
				# XXX: Cannot use ida_ua.print_operand because it returns garbage data.
				mov_reg = idc.print_operand(ea, 1).lower().strip().lstrip('[').rstrip(']')
				mov_found = True
			elif not lea_found and mov_found and mov_reg is not None and check_insn_format(ea, 'lea', [(ida_ua.o_reg, mov_reg), (ida_ua.o_mem, None)]):
				value = idc.get_operand_value(ea, 1)
				if value != ida_idaapi.BADADDR and got_plt_end_ea == ida_idaapi.BADADDR:
					got_plt_end_ea = value
				lea_found = True

		ctors_end_ea = dtors_start_ea - 0x8
		if ida_bytes.get_qword(ctors_end_ea) != 0:
			raise RuntimeError('Unexpected end of constructors table.')
		ida_bytes.create_qword(ctors_end_ea, 0x8, True)
		ida_name.set_name(ctors_end_ea, '__CTOR_END__', ida_name.SN_NOCHECK)
		ctors_start_ea = ctors_end_ea - 0x8
		while ida_bytes.get_qword(ctors_start_ea) != ida_idaapi.BADADDR:
			ctors_start_ea -= 0x8
		ida_bytes.create_qword(ctors_start_ea, 0x8, True)
		ida_name.set_name(ctors_start_ea, '__CTOR_LIST__', ida_name.SN_NOCHECK)
		ctors_end_ea += 0x8

		if preinit_array_end_ea != ida_idaapi.BADADDR:
			ida_name.set_name(preinit_array_end_ea, '_G__preinit_array_end', ida_name.SN_NOCHECK)

		return (ctors_start_ea, ctors_end_ea)

	def _fixup_dtors_segment(self):
		# static func_ptr __DTOR_LIST__[1] = { (func_ptr) (-1) };
		# ...
		# static func_ptr __DTOR_END__[1] = { (func_ptr) 0 };
		#
		# static void __do_global_dtors_aux()
		# {
		#   func_ptr* p;
		#   for (p = __DTOR_LIST__ + 1; *p; ++p)
		#     (*p)();
		# }

		ea = ida_name.get_name_ea(ida_idaapi.BADADDR, '.term_proc')
		if ea == ida_idaapi.BADADDR:
			ida_kernwin.warning('Unable to find .term_proc, cannot fixup .dtors segment.')
			return None

		last_lea_value = None
		for ea in idautils.FuncItems(ea):
			if check_insn_format(ea, 'cmp', [(ida_ua.o_mem, None), (ida_ua.o_imm, 0)]):
				value = idc.get_operand_value(ea, 0)
				if value != ida_idaapi.BADADDR:
					self.got_start_ea = value
			elif check_insn_format(ea, 'lea', [(ida_ua.o_reg, None), (ida_ua.o_mem, None)]):
				value = idc.get_operand_value(ea, 1)
				if value != ida_idaapi.BADADDR:
					last_lea_value = value
			elif check_insn_format(ea, 'add', [(ida_ua.o_reg, None), (ida_ua.o_imm, None)]):
				value = idc.get_operand_value(ea, 1)
				if value != 0x8:
					continue
				if last_lea_value is None:
					raise RuntimeError('Unexpected instructions at .term_proc().')
				break
		if last_lea_value is None:
			raise RuntimeError('Unexpected instructions at .term_proc().')

		# last_lea_value should equals to: __DTOR_LIST__ + 0x10.
		dtors_start_ea = last_lea_value - 0x10
		if ida_bytes.get_qword(dtors_start_ea) != ida_idaapi.BADADDR:
			raise RuntimeError('Unexpected start of destructors table.')
		ida_bytes.create_qword(dtors_start_ea, 0x8, True)
		ida_name.set_name(dtors_start_ea, '__DTOR_LIST__', ida_name.SN_NOCHECK)

		dtors_end_ea = dtors_start_ea + 0x8
		while ida_bytes.get_qword(dtors_end_ea) != 0:
			dtors_end_ea += 0x8
		ida_bytes.create_qword(dtors_end_ea, 0x8, True)
		ida_name.set_name(dtors_end_ea, '__DTOR_END__', ida_name.SN_NOCHECK)
		dtors_end_ea += 0x8

		return (dtors_start_ea, dtors_end_ea)

	def _fixup_bss_segment(self):
		seg = ida_segment.get_segm_by_name('.bss')
		if seg:
			# Segment already exists, skipping it.
			return False

		# We need to find last segment with R/W permissions.
		data_seg = self._find_last_rw_seg()
		if not data_seg:
			return False
		data_segment_name = ida_segment.get_segm_name(data_seg)

		# XXX: ida_bytes.next_that is not working as expected and returns address after .bss.
		bss_start_ea = ida_idaapi.BADADDR
		ea = data_seg.start_ea
		while ea != ida_idaapi.BADADDR and ea < data_seg.end_ea:
			if not idc.is_loaded(ea):
				bss_start_ea = ea
				break
			ea = ida_bytes.next_addr(ea)
		if bss_start_ea == ida_idaapi.BADADDR:
			return False
		bss_end_ea = data_seg.end_ea

		print('Creating .bss segment.')
		seg = ida_segment.segment_t()
		seg.start_ea = bss_start_ea
		seg.end_ea = bss_end_ea
		seg.type = ida_segment.SEG_BSS
		seg.bitness = data_seg.bitness
		seg.perm = data_seg.perm
		ida_segment.add_segm_ex(seg, '.bss', ida_segment.get_segm_class(data_seg), ida_segment.ADDSEG_NOSREG)

		return True

	def fixup_func_bounds(self, func, max_func_end_ea):
		end_ea = func.end_ea

		data = ida_bytes.get_bytes(end_ea, len(ps5_elf_plugin_t.UD2_INSN_BYTES))
		if not data or data != ps5_elf_plugin_t.UD2_INSN_BYTES:
			return

		end_ea += len(data)

		print('Setting function 0x%x end to 0x%x (old: 0x%x).' % (func.start_ea, end_ea, func.end_ea))
		func.end_ea = end_ea

		ida_funcs.reanalyze_function(func, func.start_ea, end_ea, False)

	def _fixup_symbols(self):
		print('Fixing up symbols.')

		if not self.symbol_table or not self.symbol_table.is_table_loaded():
			ida_kernwin.warning('Symbol table is not loaded, cannot fixup symbols.')
			return False

		if not self.string_table or not self.string_table.is_loaded():
			ida_kernwin.warning('String table is not loaded, cannot fixup symbols.')
			return False

		for i in range(self.symbol_table.get_num_entries()):
			entry = self.symbol_table.get_entry(i)
			if entry is None:
				ida_kernwin.warning('No entry for symbol table entry #%d.' % i)
				return False

			symbol = SymbolTable.Symbol(entry)

			self.symbols.append(symbol)

			if not symbol.is_object() and not symbol.is_func():
				continue

			mangled_name = self.string_table.get_string(symbol.entry['st_name'])
			if not mangled_name:
				continue

			symbol_name_enc, lid_enc, mid_enc = mangled_name.split('#')
			nid, lid, mid = ObjectInfo.decode_nid(symbol_name_enc), ObjectInfo.decode_obj_id(lid_enc), ObjectInfo.decode_obj_id(mid_enc)

			if mid not in self.modules:
				ida_kernwin.warning('No module with ID: 0x%x' % mid)
				return False
			module_name = self.modules[mid].name

			assert lid in self.libraries
			if lid not in self.libraries:
				ida_kernwin.warning('No library with ID: 0x%x' % lid)
				return False
			library_name = self.libraries[lid].name
			is_export = self.libraries[lid].is_export

			symbol_name = self.nids[nid] if nid in self.nids else nid

			symbol.set_descriptor(module_name, library_name, symbol_name, is_export)

		return True

	def _fixup_plt_segment(self):
		print('Fixing up .plt segment.')

		if not self.jmprel_reloc_table.is_table_loaded():
			ida_kernwin.warning('Jmprel relocation table is not loaded, cannot fixup .plt segment.')
			return False

		if not self.string_table.is_loaded():
			ida_kernwin.warning('String table is not loaded, cannot fixup .plt segment.')
			return False

		jmprel_entry_count = self.jmprel_reloc_table.get_num_entries()

		got_plt_seg = ida_segment.get_segm_by_name('.got.plt')
		if not got_plt_seg:
			ida_kernwin.warning('Unable to find .got.plt segment, cannot fixup .plt segment.')
			return False

		target_ea = got_plt_seg.start_ea + struct.calcsize('Q')
		xrefs = list(idautils.XrefsTo(target_ea, ida_xref.XREF_DATA))
		if not xrefs:
			ida_kernwin.warning('Unable to find xrefs to .got.plt segment, cannot fixup .plt segment.')
			return False
		xref_type, plt_start_ea = xrefs[0].type, xrefs[0].frm
		assert xref_type == ida_xref.dr_R

		base_insns = bytes.fromhex(
			'FF 35 00 00 00 00' + # push cs:<ea>
			'FF 25 00 00 00 00' + # jmp cs:<ea>
			''
		)

		stub_insns = bytes.fromhex(
			'FF 25 00 00 00 00' + # jmp qword ptr [rip]
			'68 00 00 00 00'    + # push 0
			'E9 00 00 00 00'    + # jmp 0x5
			''
		)

		# Segment should start with: push cs:<ea>
		data = ida_bytes.get_bytes(plt_start_ea, 2)
		if data[:2] != base_insns[:2]:
			ida_kernwin.warning('Unexpected .plt segment data, cannot fixup .plt segment.')
			return False

		super_seg = ida_segment.getseg(plt_start_ea)
		if not super_seg:
			ida_kernwin.warning('Unable to find segment which includes .plt, cannot fixup .plt segment.')
			return False

		# Need to find: jmp cs:<ea>
		plt_base_ea = ida_bytes.find_bytes('FF 25', range_start = plt_start_ea + len(base_insns), range_end = super_seg.end_ea, flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_CASE)
		if plt_base_ea == ida_idaapi.BADADDR:
			ida_kernwin.warning('Unable to find .plt base ea, cannot fixup .plt segment.')
			return False

		plt_end_ea = align_up(plt_base_ea + jmprel_entry_count * len(stub_insns), 0x10)

		seg = ida_segment.get_segm_by_name('.plt')
		if not seg:
			new_seg = ida_segment.segment_t()
			new_seg.start_ea = plt_start_ea
			new_seg.end_ea = plt_end_ea
			new_seg.bitness = super_seg.bitness
			new_seg.type = super_seg.type
			new_seg.perm = super_seg.perm

			print('Creating .plt segment.')
			ida_segment.add_segm_ex(new_seg, '.plt', ida_segment.get_segm_class(super_seg), 0)
		else:
			# Segment already exists, skipping it.
			pass

		idaldr_node = ida_netnode.netnode('$ IDALDR node for ids loading $')
		if not idaldr_node:
			ida_kernwin.warning('Unable to find netnode for imports.')

		for i in range(jmprel_entry_count):
			entry = self.jmprel_reloc_table.get_entry(i)
			if entry is None:
				ida_kernwin.warning('No entry for jmprel relocation table entry #%d.' % i)
				return False

			record = JmpRelRelocTable.Record(entry)

			reloc_type = record.get_type()
			if not reloc_type in [JmpRelRelocTable.R_AMD64_JUMP_SLOT]:
				ida_kernwin.warning('Unsupported relocation type 0x%x for jmprel relocation table entry #%d.' % (reloc_type, i))
				return False
			if reloc_type != self.relocation_type:
				ida_kernwin.warning('Mismatched relocation type 0x%x (should be 0x%x) for jmprel relocation table entry #%d.' % (reloc_type, self.relocation_type, i))
				return False

			symbol_idx = record.get_symbol_idx()
			if symbol_idx >= len(self.symbols):
				ida_kernwin.warning('Symbol index #%d out of range for jmprel relocation table entry #%d.' % (symbol_idx, i))
				return False
			symbol = self.symbols[symbol_idx]

			if not symbol.has_descriptor():
				ida_kernwin.warning('Symbol #%d has no descriptor for jmprel relocation table entry #%d.' % (symbol_idx, i))
				return False

			name = symbol.get_name()
			name_ex = symbol.get_name_ex()
			comment = symbol.get_name_comment()

			stub_name = '/B%s' % name_ex
			stub_ptr_name = '/PG%s' % name_ex

			stub_ptr_ea = record.entry['r_offset']
			stub_ea = ida_bytes.get_qword(record.entry['r_offset'])
			func_ea = plt_base_ea + i * len(stub_insns)

			#print('Renaming stub pointer %s to %s at 0x%x.' % (ida_name.get_name(stub_ptr_ea), stub_ptr_name, stub_ptr_ea))
			ida_name.set_name(stub_ptr_ea, stub_ptr_name, ida_name.SN_NOCHECK)
			ida_bytes.set_cmt(stub_ptr_ea, '', False)

			#print('Renaming stub %s to %s at 0x%x.' % (ida_name.get_name(stub_ea), stub_name, stub_ea))
			ida_name.set_name(stub_ea, stub_name, ida_name.SN_NOCHECK)
			ida_bytes.set_cmt(stub_ea, '', False)

			func = ida_funcs.get_func(func_ea)
			if not func:
				ida_funcs.add_func(func_ea, ida_idaapi.BADADDR)

			#print('Renaming function %s to %s at 0x%x.' % (ida_name.get_name(func_ea), name, func_ea))
			ida_name.set_name(func_ea, name, ida_name.SN_NOCHECK)
			ida_bytes.set_cmt(func_ea, comment, False)

			func = ida_funcs.get_func(stub_ea)
			if not func:
				ida_funcs.add_func(stub_ea, ida_idaapi.BADADDR)

			ea = ida_name.get_name_ea(func_ea, name)
			if ea != ida_idaapi.BADADDR:
				func = ida_funcs.get_func(ea)
				if func:
					func.flags |= ida_funcs.FUNC_LIB
					ida_funcs.update_func(func)

			ea = ida_name.get_name_ea(stub_ea, stub_name)
			if ea != ida_idaapi.BADADDR:
				func = ida_funcs.get_func(ea)
				if func:
					func.flags |= ida_funcs.FUNC_LIB
					ida_funcs.update_func(func)

			if idaldr_node:
				idaldr_node.supset_ea(stub_ea, stub_name, ida_netnode.stag)

		return True

	def _fixup_relocations(self):
		print('Fixing up relocations.')

		if not self.rela_reloc_table.is_table_loaded():
			ida_kernwin.warning('Rela relocation table is not loaded, cannot fixup relocations.')
			return False

		if not self.string_table.is_loaded():
			ida_kernwin.warning('String table is not loaded, cannot fixup relocations.')
			return False

		idaldr_node = ida_netnode.netnode('$ IDALDR node for ids loading $')
		if not idaldr_node:
			ida_kernwin.warning('Unable to find netnode for imports.')

		rela_entry_count = self.rela_reloc_table.get_num_entries()

		for i in range(rela_entry_count):
			entry = self.rela_reloc_table.get_entry(i)
			if entry is None:
				ida_kernwin.warning('No entry for rela relocation table entry #%d.' % i)
				return False

			record = RelaRelocTable.Record(entry)
			reloc_type = record.get_type()

			ea, addend = as_uint64(record.entry['r_offset']), as_uint64(record.entry['r_addend'])

			if reloc_type in [RelaRelocTable.R_AMD64_GLOB_DAT, RelaRelocTable.R_AMD64_64]:
				symbol_idx = record.get_symbol_idx()
				if symbol_idx < len(self.symbols):
					symbol = self.symbols[symbol_idx]

					if symbol.has_descriptor():
						name = symbol.get_name()
						if name:
							ea = ida_bytes.get_qword(ea)
							if ea != ida_idaapi.BADADDR:
								#print('Renaming symbol at 0x%x to %s.' % (ea, name))
								ida_name.set_name(ea, name, ida_name.SN_NOCHECK)

								if idaldr_node:
									idaldr_node.supset_ea(ea, name, ida_netnode.stag)
					else:
						# TODO: Is it correct?
						#print('Warning! Symbol #%d has no descriptor for rela relocation table entry #%d.' % (symbol_idx, i))
						continue
				else:
					# TODO: Is it correct?
					#print('Warning! Rela relocation table entry #%d have invalid symbol idx #%d.' % (i, symbol_idx))
					continue
			else:
				print('Warning! Unsupported relocation type 0x%x for rela relocation table entry #%d.' % (reloc_type, i))
				continue

		return True

	def _fixup_exports(self):
		print('Fixing up exports.')

		ea_ordinal_map = {}

		for i in range(ida_entry.get_entry_qty()):
			ordinal = ida_entry.get_entry_ordinal(i)
			ea = ida_entry.get_entry(ordinal)
			ea_ordinal_map[ea] = ordinal

		for i, symbol in enumerate(self.symbols):
			if not symbol.is_export and not symbol.is_object() and not symbol.is_func():
				continue

			if not symbol.has_descriptor():
				continue

			ea, size = symbol.entry['st_value'], symbol.entry['st_size']
			if ea == 0 or ea == ida_idaapi.BADADDR:
				continue

			func = ida_funcs.get_func(ea)
			if not func:
				ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
				ida_ua.create_insn(ea)
				ida_funcs.add_func(ea, ea + size)

			name = symbol.get_name()

			print('Setting name %s to exported function at 0x%x.' % (name, ea))
			if ea in ea_ordinal_map:
				ordinal = ea_ordinal_map[ea]
				ida_entry.rename_entry(ordinal, name, ida_entry.AEF_UTF8)
			else:
				ida_name.set_name(ea, name)
			ida_bytes.set_cmt(ea, '', False)

		return True

	def _fixup_dynsym_segment(self):
		print('Deleting .dynsym segment.')

		seg = ida_segment.get_segm_by_name('.dynsym')
		if not seg:
			ida_kernwin.warning('Unable to find .dynsym segment, cannot fixup .dynsym segment.')
			return False

		ida_segment.del_segm(seg.start_ea, ida_segment.SEGMOD_KILL | ida_segment.SEGMOD_SILENT)

		return True

	def _mark_noret_funcs(self):
		names = [
			'exit', 'exit1', 'abort',
			'__stack_chk_fail',
			'_ZNSt9bad_allocD0Ev', '_ZNSt9bad_allocD1Ev', '_ZNSt9bad_allocD2Ev', '_ZSt11_Xbad_allocv',
			'_ZNSt16invalid_argumentD0Ev', '_ZNSt16invalid_argumentD1Ev', '_ZNSt16invalid_argumentD2Ev', '_ZSt18_Xinvalid_argumentPKc',
			'_ZNSt12length_errorD0Ev', '_ZNSt12length_errorD1Ev', '_ZNSt12length_errorD2Ev', '_ZSt14_Xlength_errorPKc',
			'_ZNSt12out_of_rangeD0Ev', '_ZNSt12out_of_rangeD1Ev', '_ZNSt12out_of_rangeD2Ev', '_ZSt14_Xout_of_rangePKc',
			'_ZNSt14overflow_errorD0Ev', '_ZNSt14overflow_errorD1Ev', '_ZNSt14overflow_errorD2Ev', '_ZSt16_Xoverflow_errorPKc',
			'_ZNSt13runtime_errorD0Ev', '_ZNSt13runtime_errorD1Ev', '_ZNSt13runtime_errorD2Ev', '_ZSt15_Xruntime_errorPKc',
			'_ZNSt17bad_function_callD0Ev', '_ZNSt17bad_function_callD1Ev', '_ZNSt17bad_function_callD2Ev', '_ZSt19_Xbad_function_callv',
			'_ZNSt11regex_errorD0Ev', '_ZNSt11regex_errorD1Ev', '_ZNSt11regex_errorD2Ev',
			'_ZSt10_Rng_abortPKc',
			'_ZSt19_Throw_future_errorRKSt10error_code',
			'_ZSt25_Rethrow_future_exceptionPv', '_ZSt25_Rethrow_future_exceptionSt13exception_ptr',
		]

		for name in names:
			ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
			if ea == ida_idaapi.BADADDR:
				continue

			func = ida_funcs.get_func(ea)
			if not func:
				continue

			func.flags |= ida_funcs.FUNC_NORET
			ida_funcs.update_func(func)

			ida_auto.reanalyze_callers(ea, True)

	def _find_last_rw_seg(self):
		rw_seg = None

		seg, first_seg = ida_segment.get_last_seg(), ida_segment.get_first_seg()
		while seg and seg != first_seg:
			name = ida_segment.get_segm_name(seg)
			sclass = ida_segment.get_segm_class(seg)
			if seg.perm == ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE:
				rw_seg = seg
				break
			seg = ida_segment.get_prev_seg(seg.start_ea)

		return rw_seg

	def post_initial_analysis(self):
		self.elf = ElfUtil()
		if not self.elf.is_inited():
			raise RuntimeError('Netnode for elf is not initialized.')

		print('Performing post initial auto analysis.')

		for i in range(ida_segment.get_segm_qty()):
			seg = ida_segment.getnseg(i)
			if seg:
				self._fixup_segment(seg)

		self._parse_extra_segments()
		self._fixup_segment_perms()
		self._link_segments_with_phdrs()
		self._fixup_padding_segment()
		self._fixup_param_segment()
		self._fixup_data_segment()
		self._fixup_init_fini_segments()
		self._fixup_eh_segments()
		self._fixup_ctors_dtors_segments()
		self._fixup_got_segments()
		self._fixup_bss_segment()
		self._fixup_extra_segments()
		self._fixup_symbols()

		# Allow to rename jump functions now because we did set up correct symbol names already.
		ida_ida.inf_set_rename_jumpfunc(True) # Rename jump functions as J_.

		self._fixup_plt_segment()
		self._fixup_relocations()
		self._fixup_exports()
		self._fixup_dynsym_segment()

		self._mark_noret_funcs()

		if self.soname is not None:
			print('Name: %s' % self.soname)
		if self.orig_file_path is not None:
			print('Original file path: %s' % self.orig_file_path)

		if self.init_proc_ea != ida_idaapi.BADADDR:
			print('Address of .init_proc function: 0x%x' % self.init_proc_ea)
		if self.term_proc_ea != ida_idaapi.BADADDR:
			print('Address of .term_proc function: 0x%x' % self.term_proc_ea)

		if self.needed_modules:
			print('Needed modules: %s' % ', '.join(self.needed_modules))
		for id, info in self.modules.items():
			print('Module #%03d: %s' % (id, repr(info)))
		for id, info in self.libraries.items():
			print('Library #%03d: %s' % (id, repr(info)))

		if self.relocation_type is not None:
			print('Relocation type: 0x%x' % self.relocation_type)

	def run(self, arg):
		ida_kernwin.warning('Running as script is not possible.')
		return False

def PLUGIN_ENTRY():
	return ps5_elf_plugin_t()
