from dataclasses import dataclass
from typing import Callable, List, Dict


@dataclass
class Hook:
    func: Callable
    tags: List[str]


@dataclass
class HookDefinition:
    """
    The definition for a hook.  This is comprised of a name and a signature.

    Example:

        >>> hook_def = HookDefinition(
            name='pre_save",
            signature="Callable[[ObjectStore, LDAPRecord], None]
        )
        >>> hook_def.name
        "pre_save"
        >>> hook_def.signature
        "Callable[[ObjectStore, LDAPRecord], None]"

    Attributes:
        name: the name of the hook, e.g. "pre_save"
        signature: the python type annotation signature that the hook should
            implement, e.g. "Callable[[ObjectStore, LDAPRecord], None]"
    """
    name: str
    signature: str


class HookRegistry:

    def __init__(self) -> None:
        self.__hooks: Dict[str, List[Hook]] = {}
        self.__definitions: Dict[str, str] = {}

    @property
    def definitions(self) -> List[HookDefinition]:
        """
        Return a list of known hooks definitions as
        """
        definitions = []
        for name, signature in self.__definitions.items():
            definitions.append(HookDefinition(name=name, signature=signature))
        return definitions

    def register_hook_definition(self, hook_name: str, signature: str) -> None:
        """
        Register a hook definition.  Hook definitions define what hooks exist, and what their
        function signature must be.

        Example:

            >>> hooks = HookRegistry()
            >>> hooks.register_definition('pre_set', 'Callable[[ObjectStore, LDAPRecord], None]')

        Args:
            hook_name: the name of the hook
            signature: A string in Python type annotation format describing the
                signature the hook must have
        """
        if hook_name in self.__definitions:
            raise ValueError('"{hook_name}" is already a defined hook')
        self.__definitions[hook_name] = signature

    def register_hook(self, hook_name: str, func: Callable, tags: List[str] = None) -> None:
        """
        Register a hook for this object store.  Hooks are functions with this signature::

            def myhook(store: ObjectStore, record: LDAPRecord) -> None:

        Use hooks to implement side-effects on select :py:class:`ObjectStore` methods.

        Example:

            To register a hook that updates a an attribute named ``modifyTimestamp`
            before saving a record to the object store, you could define the hook
            like so:

                def update_modifyTimestamp(store: ObjectStore, record: LDAPRecord) -> None:
                    record[1]['modifyTimestamp'] = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%SZ')

            and register it as a `pre_modify` method like so:

                >>> store = ObjectStore()
                >>> store.register_hook('pre_set', update_modifyTimestamp)

        Note:
            Hooks for a particular ``hook_name`` are applied in the order they are registered.

        Args:
            hook_name: the name of the known hook to which register this ``func``
            func: the hook function

        Raises:
            ValueError: ``hook_name`` is not a known hook
        """
        if hook_name not in self.__definitions:
            raise ValueError(f'"{hook_name}" is not a known hook')
        if tags is None:
            tags = []
        if hook_name not in self.__hooks:
            self.__hooks[hook_name] = []
        hook = Hook(func=func, tags=tags)
        self.__hooks[hook_name].append(hook)

    def get(self, hook_name: str, tags: List[str] = None) -> List[Callable]:
        """
        Get a list of hook callables for the hook named by ``name``, possibly
        filtering hooks by tag.

        Tag filtering rules:

        * If a hook has no tags associated with it, it always applies.
        * Otherwise, if at least one of the hooks tags are present in ``tags``,
          the hook applies.

        Args:
            hook_name: the name of the hook for which to return functions

        Keyword Arguments:
            tags: if provided, filter the available hook functions to include
                only those with tags listed in ``tags``

        Raises:
            ValueError: there is no known hook with name ``hook_name``

        Returns:
            A list of callables.
        """
        valid_hooks = []
        if hook_name not in self.__definitions:
            raise ValueError(f'"{hook_name} is not a known hook')
        if not tags:
            tags = []
        tags_set = set(tags)
        for h in self.__hooks.get(hook_name, []):
            if not h.tags:
                # If the hook itself has no tags, it always applies
                valid_hooks.append(h.func)
            elif tags_set.intersection(h.tags):
                # Otherwise, some of h.tags must be in tags_set
                valid_hooks.append(h.func)
        return valid_hooks


hooks = HookRegistry()

hooks.register_hook_definition('post_objectstore_init', 'Callable[[ObjectStore], None]')
hooks.register_hook_definition('pre_set', 'Callable[[ObjectStore, LDAPRecord, Optional[str]], None]')
hooks.register_hook_definition('post_set', 'Callable[[ObjectStore, LDAPRecord, Optional[str]], None]')
hooks.register_hook_definition('pre_copy', 'Callable[[ObjectStore, str], None]')
hooks.register_hook_definition('post_copy', 'Callable[[ObjectStore, LDAPData], LDAPData]')
hooks.register_hook_definition('pre_create', 'Callable[[ObjectStore, str, AddModList, Optional[str]], None]')
hooks.register_hook_definition('post_create', 'Callable[[ObjectStore, LDAPRecord, Optional[str]], None]')
hooks.register_hook_definition('pre_update', 'Callable[[ObjectStore, str, ModList, Optional[str]], None]')
hooks.register_hook_definition('post_update', 'Callable[[ObjectStore, LDAPRecord, Optional[str]], None]')
hooks.register_hook_definition('pre_delete', 'Callable[[ObjectStore, LDAPRecord, Optional[str]], None]')
hooks.register_hook_definition('post_delete', 'Callable[[ObjectStore, LDAPRecord, Optional[str]], None]')
hooks.register_hook_definition('pre_register_object', 'Callable[[ObjectStore, LDAPRecord], None]')
hooks.register_hook_definition('post_register_object', 'Callable[[ObjectStore, LDAPRecord], None]')
hooks.register_hook_definition('pre_register_objects', 'Callable[[ObjectStore, List[LDAPRecord]], None]')
hooks.register_hook_definition('post_register_objects', 'Callable[[ObjectStore], None]')
hooks.register_hook_definition('pre_load_objects', 'Callable[[ObjectStore, str], None]')
hooks.register_hook_definition('post_load_objects', 'Callable[[ObjectStore], None]')
