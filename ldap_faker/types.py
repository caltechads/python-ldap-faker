from typing import Dict, Tuple, List, Union

from case_insensitive_dict import CaseInsensitiveDict

# ====================================
# Types
# ====================================

LDAPData = Dict[str, List[bytes]]
CILDAPData = CaseInsensitiveDict[str, List[str]]
LDAPRecord = Tuple[str, LDAPData]
LDAPSearchResult = List[LDAPRecord]
LDAPSearchDirectory = CaseInsensitiveDict[str, LDAPSearchResult]
LDAPObjectStore = CaseInsensitiveDict[str, CILDAPData]
RawLDAPObjectStore = CaseInsensitiveDict[str, LDAPData]
LDAPOptionValue = Union[int, str]
LDAPOptionStore = Dict[int, LDAPOptionValue]
ModList = List[Tuple[int, str, List[bytes]]]
AddModList = List[Tuple[str, List[bytes]]]
LDAPFixtureList = Union[str, List[Tuple[str, str]]]
