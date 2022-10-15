from typing import Dict, Tuple, List, Union

from case_insensitive_dict import CaseInsensitiveDict
import ldap

# ====================================
# Types
# ====================================

# LDAP records and objects
LDAPData = Dict[str, List[bytes]]
CILDAPData = CaseInsensitiveDict[str, List[str]]
LDAPRecord = Tuple[str, LDAPData]
LDAPSearchResult = List[LDAPRecord]
LDAPSearchDirectory = CaseInsensitiveDict[str, LDAPSearchResult]
LDAPObjectStore = CaseInsensitiveDict[str, CILDAPData]
RawLDAPObjectStore = CaseInsensitiveDict[str, LDAPData]
Attrlist = CaseInsensitiveDict[str, str]

# Return values
# result: (result_type, result_data)
Result = Tuple[Union[int, str], LDAPSearchResult]
# result: (result_type, result_data, decoded server controls)
Result2 = Tuple[Union[int, str], LDAPSearchResult, int, List[ldap.controls.LDAPControl]]
# result: (result_type, result_data, decoded server controls)
Result3 = Tuple[Union[int, str], LDAPSearchResult, int, List[ldap.controls.LDAPControl]]

# Options
LDAPOptionValue = Union[int, str]
LDAPOptionStore = Dict[int, LDAPOptionValue]

# Modlists
ModList = List[Tuple[int, str, List[bytes]]]
AddModList = List[Tuple[str, List[bytes]]]

# unittest support
LDAPFixtureList = Union[str, Tuple[str, List[str]], List[Tuple[str, str, List[str]]]]
