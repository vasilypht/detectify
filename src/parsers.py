def extract_texts(extractor) -> list[str]:
    texts = []

    texts.extend(MagicParser().transform(extractor.magic))
    texts.extend(TypeTagParser().transform(extractor.type_tag))
    texts.extend(TypeTagsParser().transform(extractor.type_tags))
    texts.extend(DetectitEasyParser().transform(extractor.detectiteasy))
    texts.extend(TypeExtensionParser().transform(extractor.type_extension))
    texts.extend(ImportListParser().transform(extractor.import_list))
    texts.extend(MitreAttackTechniquesParser().transform(extractor.mitre_attack_techniques))
    texts.extend(SignatureMatchesParser().transform(extractor.signature_matches))
    texts.extend(CommandExecutionsParser().transform(extractor.command_executions))
    texts.extend(ProcessesTreeParser().transform(extractor.processes_tree))
    texts.extend(ProcessesInjectedParser().transform(extractor.processes_injected))
    texts.extend(ProcessesCreatedParser().transform(extractor.processes_created))
    texts.extend(ProcessesTerminatedParser().transform(extractor.processes_terminated))
    texts.extend(FilesOpenedParser().transform(extractor.files_opened))
    texts.extend(FilesCopiedParser().transform(extractor.files_copied))
    texts.extend(FilesDroppedParser().transform(extractor.files_dropped))
    texts.extend(FilesWrittenParser().transform(extractor.files_written))
    texts.extend(FilesAttributeChangedParser().transform(extractor.files_attribute_changed))
    texts.extend(MutexesOpenedParser().transform(extractor.mutexes_opened))
    texts.extend(MutexesCreatedParser().transform(extractor.mutexes_created))
    texts.extend(ModulesLoadedParser().transform(extractor.modules_loaded))
    texts.extend(RegistryKeysOpenedParser().transform(extractor.registry_keys_opened))
    texts.extend(RegistryKeysSetParser().transform(extractor.registry_keys_set))
    texts.extend(RegistryKeysDeletedParser().transform(extractor.registry_keys_deleted))
    texts.extend(IpTrafficParser().transform(extractor.ip_traffic))
    texts.extend(DNSLookupsParser().transform(extractor.dns_lookups))
    texts.extend(ServicesStartedParser().transform(extractor.services_started))
    texts.extend(ServicesOpenedParser().transform(extractor.services_opened))
    texts.extend(CallsHighlightedParser().transform(extractor.calls_highlighted))
    texts.extend(HTTPConversationsParser().transform(extractor.http_conversations))
    texts.extend(SignalsHookedParser().transform(extractor.signals_hooked))
    texts.extend(WindowsSearchedParser().transform(extractor.windows_searched))
    return texts


class TypeTagsParser:
    def __init__(self):
        self.tag = '[type_tags]'

    def transform(self, data: list[str]) -> list[str]:
        if not data:
            return []

        formatted_result = map(lambda x: f'{self.tag} {x}', data)
        return list(formatted_result)


class TypeTagParser:
    def __init__(self):
        self.tag = '[type_tag]'

    def transform(self, data: str) -> list[str]:
        if not data:
            return []

        formatted_str = f'{self.tag} {data}'
        return [formatted_str]


class DetectitEasyParser:
    def __init__(self):
        self.tag = '[detectiteasy]'

    def transform(self, data: dict) -> list[str]:
        if not data:
            return []

        filetype = data.get('filetype', '-')

        formatted_strings = map(
            lambda x: ', '.join(
                [
                    filetype,
                    x.get('info', '-'),
                    x.get('version', '-'),
                    x.get('type', '-'),
                    x.get('name', '-'),
                ]
            ),
            data.get('values', [])
        )

        formatted_result = map(lambda x: f'{self.tag} {x}', formatted_strings)
        return list(formatted_result)


class TypeExtensionParser:
    def __init__(self):
        self.tag = '[type_extension]'

    def transform(self, data: str) -> list[str]:
        if not data:
            return []

        formatted_str = f'{self.tag} {data}'
        return [formatted_str]


class ImportListParser:
    def __init__(self):
        self.tag = '[import_list]'

    def transform(self, data: list[dict]) -> list[str]:
        if not data:
            return []

        formatted_strings = []

        for lib in data:
            lib_name = lib['library_name']
            formatted_import = list(map(lambda x: f'{lib_name}: {x}', lib.get('imported_functions')))
            formatted_strings.extend(formatted_import)

        formatted_result = map(lambda x: f'{self.tag} {x}', formatted_strings)
        return list(formatted_result)


class MagicParser:
    def __init__(self):
        self.tag = '[magic]'

    def transform(self, data: str) -> list[str]:
        if not data:
            return []

        formatted_str = f'{self.tag} {data}'
        return [formatted_str]


class ModulesLoadedParser:
    def __init__(self):
        self.tag = '[modules_loaded]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, modules = max(data.items(), key=lambda x: len(x[1]))
        else:
            modules = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', modules)
        return list(formatted_result)


class IpTrafficParser:
    def __init__(self):
        self.tag = '[ip_traffic]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, traffic = max(data.items(), key=lambda x: len(x[1]))
        else:
            traffic = data.get(sandbox, [])

        formatted_strings = map(
            lambda x: ' '.join(
                [
                    str(x.get('transport_layer_protocol', '-')),
                    str(x.get('destination_ip', '-')),
                    str(x.get('destination_port', '-')),
                ]
            ),
            traffic
        )
        formatted_result = map(lambda x: f'{self.tag} {x}', formatted_strings)
        return list(formatted_result)


class DNSLookupsParser:
    def __init__(self):
        self.tag = '[dns_lookups]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, lookups = max(data.items(), key=lambda x: len(x[1]))
        else:
            lookups = data.get(sandbox, [])

        hostnames = [lookup.get('hostname', '-') for lookup in lookups]

        formatted_result = map(lambda x: f'{self.tag} {x}', hostnames)
        return list(formatted_result)


class ProcessesCreatedParser:
    def __init__(self):
        self.tag = '[processes_created]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, processes = max(data.items(), key=lambda x: len(x[1]))
        else:
            processes = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', processes)
        return list(formatted_result)


class CommandExecutionsParser:
    def __init__(self):
        self.tag = '[command_executions]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, commands = max(data.items(), key=lambda x: len(x[1]))
        else:
            commands = data.get(sandbox, [])

        # filter empty commands
        filtered_commands = filter(lambda x: x.strip(), commands)
        formatted_result = map(lambda x: f'{self.tag} {x}', filtered_commands)
        return list(formatted_result)


class FilesOpenedParser:
    def __init__(self):
        self.tag = '[files_opened]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, files = max(data.items(), key=lambda x: len(x[1]))
        else:
            files = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', files)
        return list(formatted_result)


class FilesDeletedParser:
    def __init__(self):
        self.tag = '[files_deleted]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, files = max(data.items(), key=lambda x: len(x[1]))
        else:
            files = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', files)
        return list(formatted_result)


class FilesDroppedParser:
    def __init__(self):
        self.tag = '[files_dropped]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, files = max(data.items(), key=lambda x: len(x[1]))
        else:
            files = data.get(sandbox, [])

        files = [info.get('path', '') for info in files]

        formatted_result = map(lambda x: f'{self.tag} {x}', files)
        return list(formatted_result)


class FilesCopiedParser:
    def __init__(self):
        self.tag = '[files_copied]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, files = max(data.items(), key=lambda x: len(x[1]))
        else:
            files = data.get(sandbox, [])

        formatted_strings = []
        for file_info in files:
            src = file_info['source']
            dest = file_info['destination']
            formatted_str = f"'{src}' to '{dest}'"
            formatted_strings.append(formatted_str)

        formatted_result = map(lambda x: f'{self.tag} {x}', formatted_strings)
        return list(formatted_result)


class FilesWrittenParser:
    def __init__(self):
        self.tag = '[files_written]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, files = max(data.items(), key=lambda x: len(x[1]))
        else:
            files = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', files)
        return list(formatted_result)


class MitreAttackTechniquesParser:
    def __init__(self):
        self.tag = '[mitre_attack_techniques]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        format_map = map(lambda x: f'{x["id"]} {x["signature_description"]}', info)
        formatted_result = map(lambda x: f'{self.tag} {x}', format_map)
        return list(formatted_result)


class SignalsHookedParser:
    def __init__(self):
        self.tag = '[signals_hooked]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', info)
        return list(formatted_result)


class HTTPConversationsParser:
    def __init__(self):
        self.tag = '[http_conversations]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        format_map = map(lambda x: f"{x['request_method']} {x['url']}", info)
        formatted_result = map(lambda x: f'{self.tag} {x}', format_map)
        return list(formatted_result)


class FilesAttributeChangedParser:
    def __init__(self):
        self.tag = '[files_attribute_changed]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', info)
        return list(formatted_result)


class ServicesStartedParser:
    def __init__(self):
        self.tag = '[services_started]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', info)
        return list(formatted_result)


class ServicesOpenedParser:
    def __init__(self):
        self.tag = '[services_opened]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', info)
        return list(formatted_result)


class WindowsSearchedParser:
    def __init__(self):
        self.tag = '[windows_searched]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', info)
        return list(formatted_result)


class ProcessesTerminatedParser:
    def __init__(self):
        self.tag = '[processes_terminated]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', info)
        return list(formatted_result)


class ProcessesInjectedParser:
    def __init__(self):
        self.tag = '[processes_injected]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', info)
        return list(formatted_result)


class RegistryKeysDeletedParser:
    def __init__(self):
        self.tag = '[registry_keys_deleted]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', info)
        return list(formatted_result)


class SignatureMatchesParser:
    def __init__(self):
        self.tag = '[signature_matches]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        format_map = map(lambda x: x.get('description'), info)
        format_filter = filter(lambda x: x is not None, format_map)
        formatted_result = map(lambda x: f'{self.tag} {x}', format_filter)
        # drop uniques
        return list(set(formatted_result))


class RegistryKeysOpenedParser:
    def __init__(self):
        self.tag = '[registry_keys_opened]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', info)
        return list(formatted_result)


class RegistryKeysSetParser:
    def __init__(self):
        self.tag = '[registry_keys_set]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        format_map = map(lambda x: f"{x.get('key', '')} -> {x.get('value', '<empty>')}", info)
        formatted_result = map(lambda x: f'{self.tag} {x}', format_map)
        return list(formatted_result)


class CallsHighlightedParser:
    def __init__(self):
        self.tag = '[calls_highlighted]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', info)
        return list(formatted_result)


class MutexesOpenedParser:
    def __init__(self):
        self.tag = '[mutexes_opened]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', info)
        return list(formatted_result)


class MutexesCreatedParser:
    def __init__(self):
        self.tag = '[mutexes_created]'

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, info = max(data.items(), key=lambda x: len(x[1]))
        else:
            info = data.get(sandbox, [])

        formatted_result = map(lambda x: f'{self.tag} {x}', info)
        return list(formatted_result)


class ProcessesTreeParser:
    def __init__(self):
        self.tag = '[processes_tree]'

    @staticmethod
    def __parse_tree(tree):
        def parse_node(node, item: list = None):
            if item is None:
                item = []
            item.append(node['name'])

            if node.get('children') is None:
                return [item]

            items = []
            for child_node in node['children']:
                child_items = parse_node(child_node, item.copy())
                items.extend(child_items)

            return items

        return [item for node in tree for item in parse_node(node)]

    def transform(self, data: dict, sandbox: str = None) -> list[str]:
        if not data:
            return []

        if sandbox is None:
            _, tree = max(data.items(), key=lambda x: len(x[1]))
        else:
            tree = data.get(sandbox, [])

        nodes = self.__parse_tree(tree)
        formatted_result = map(lambda x: f'{self.tag} {" -> ".join(x)}', nodes)
        return list(formatted_result)
