from typing import TYPE_CHECKING

from case_insensitive_dict import CaseInsensitiveDict

if TYPE_CHECKING:
    import ldap

# ====================================
# Types
# ====================================

# LDAP records and objects
LDAPData = dict[str, list[bytes]]
CILDAPData = CaseInsensitiveDict[str, list[str]]
LDAPRecord = tuple[str, LDAPData]
LDAPSearchResult = list[LDAPRecord]
LDAPSearchDirectory = CaseInsensitiveDict[str, LDAPSearchResult]
LDAPObjectStore = CaseInsensitiveDict[str, CILDAPData]
RawLDAPObjectStore = CaseInsensitiveDict[str, LDAPData]
Attrlist = CaseInsensitiveDict[str, str]

# Return values
# result: (result_type, result_data)  # noqa: ERA001
Result = tuple[int | str, LDAPSearchResult]
# result: (result_type, result_data, decoded server controls)
Result2 = tuple[int | str, LDAPSearchResult, int, list["ldap.controls.LDAPControl"]]  # type: ignore[attr-defined]
# result: (result_type, result_data, decoded server controls)
Result3 = tuple[int | str, LDAPSearchResult, int, list["ldap.controls.LDAPControl"]]  # type: ignore[attr-defined]

# Options
LDAPOptionValue = int | str
LDAPOptionStore = dict[int, LDAPOptionValue]

# Modlists
ModList = list[tuple[int, str, list[bytes]]]
AddModList = list[tuple[str, list[bytes]]]

# unittest support
LDAPFixtureList = str | tuple[str, list[str]] | list[tuple[str, str, list[str]]]
