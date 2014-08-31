from pe_gen import *



class IMAGE_OPTIONAL_HEADER_PE32_PLUS(Structure):
    _fields_ = [('Magic', c_ushort),
                ('MajorLinkerVersion', c_ubyte),
                ('MinorLinkerVersion', c_ubyte),
                ('SizeOfCode', c_uint),
                ('SizeOfInitializedData', c_uint),
                ('SizeOfUninitializedData', c_uint),
                ('AddressOfEntryPoint', c_uint),
                ('BaseOfCode', c_uint),
                ('ImageBase', c_ulonglong),
                ('SectionAlignment', c_uint),
                ('FileAlignment', c_uint),
                ('MajorOperatingSystemVersion', c_ushort),
                ('MinorOperatingSystemVersion', c_ushort),
                ('MajorImageVersion', c_ushort),
                ('MinorImageVersion', c_ushort),
                ('MajorSubsystemVersion', c_ushort),
                ('MinorSubsystemVersion', c_ushort),
                ('Win32VersionValue', c_uint),
                ('SizeOfImage', c_uint),
                ('SizeOfHeaders', c_uint),
                ('CheckSum', c_uint),
                ('Subsystem', c_ushort),
                ('DllCharacteristics', c_ushort),
                ('SizeOfStackReserve', c_ulonglong),
                ('SizeOfStackCommit', c_ulonglong),
                ('SizeOfHeapReserve', c_ulonglong),
                ('SizeOfHeapCommit', c_ulonglong),
                ('LoaderFlags', c_uint),
                ('NumberOfRvaAndSizes', c_uint),
                ('DataDirectory', IMAGE_DATA_DIRECTORY * 16)]


class IMAGE_NT_HEADERS(Structure):
    _fields_ = [('Signature', c_char * 4),
                ('FileHeader', IMAGE_FILE_HEADER),
                ('OptionalHeader', IMAGE_OPTIONAL_HEADER_PE32_PLUS)]
