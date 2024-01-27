import json
from pathlib import Path
from typing import Optional

from detectify.helpers.dict import safe_get


DEFAULT_FEATURES = [
    'type_tags',
    'type_tag',
    'detectiteasy',
    'type_extension',
    'import_list',
    'magic',

    'mitre_attack_techniques',
    'signature_matches',
    'registry_keys_opened',
    'registry_keys_set',
    'registry_keys_deleted',
    'command_executions',
    'mutexes_opened',
    'mutexes_created',
    'dns_lookups',
    'calls_highlighted',
    'processes_tree',
    'processes_created',
    'processes_terminated',
    'processes_injected',
    'modules_loaded',
    'files_attribute_changed',
    'files_deleted',
    'files_dropped',
    'files_copied',
    'files_written',
    'files_opened',
    'services_started',
    'services_opened',
    'ip_traffic',
    'http_conversations',
    'signals_hooked',
    'windows_searched',
]


class VirusTotalFeatureExtractor:
    def __init__(
            self,
            *,
            report_files: Optional[dict] = None,
            report_files_behaviours: Optional[dict] = None,
    ) -> None:
        """Text feature extractor from VirusTotal reports.

        Parameters
        ----------
        report_files : Optional[dict], optional
            Information about the file in json format. Retrieved from API .../files/{id}, by default None
        report_files_behaviours : Optional[dict], optional
            Information about the file in json format. Retrieved from API .../files_behaviours/{id}, by default None
        """
        self._report_files = report_files if isinstance(report_files, dict) else {}
        self._sandbox_reports = {}
        
        if isinstance(report_files_behaviours, dict):
            for _report in report_files_behaviours.get('data', []):
                sandbox_name = _report['attributes']['sandbox_name']
                self._sandbox_reports[sandbox_name] = _report

    @classmethod
    def from_json(cls, file_path: Path | str) -> 'VirusTotalFeatureExtractor':
        """Creating an extractor from a json file.

        Parameters
        ----------
        file_path : Path | str
            Path to the file.

        Returns
        -------
        VirusTotalFeatureExtractor
            New extractor.
        """
        with open(file_path, 'r') as file:
            data = json.load(file)

        return cls(
            report_files=data.get('files'),
            report_files_behaviours=data.get('files_behaviours'),
        )

    def extract_all(
            self,
            exclude: Optional[list] = None,
            error: Optional[str] = 'raise',
            features_kwargs: Optional[dict] = None,
    ) -> list[str]:
        """Method for extracting all features from a report.

        Parameters
        ----------
        exclude : Optional[list], optional
            List of features that need to be excluded during extraction, by default None
        error : Optional[str], optional
            Error processing, by default 'raise'
        features_kwargs : Optional[dict], optional
            Keyword arguments for features, by default None

        Returns
        -------
        list[str]
            List of feature lines.

        Raises
        ------
        Exception
            Error calling method when extracting features.
        """
        if features_kwargs is None:
            features_kwargs = {}

        features_iter = map(lambda feature: feature, DEFAULT_FEATURES)

        if exclude is not None:
            features_iter = filter(lambda feature: feature not in exclude, features_iter)

        result_texts = []
        for feature in features_iter:
            try:
                feature_method = getattr(self, feature)
                feature_method_kwargs = features_kwargs.get(feature, {})
                texts_ = feature_method(**feature_method_kwargs)
                result_texts.extend(texts_)

            except Exception as e:
                if error == 'raise':
                    raise Exception('Some error on extract_all(...)') from e

        return result_texts

    @property
    def sandboxes(self) -> list[str]:
        """Available sandboxes for extraction.

        Returns
        -------
        list[str]
            List of available sandboxes.
        """
        return list(self._sandbox_reports)

    def _get_attribute_from_report(self, attribute: str) -> dict:
        """For /files data. Obtaining raw characteristic data from the report.

        Parameters
        ----------
        attribute : str
            Attribute (feature) name.

        Returns
        -------
        dict
            Attribute data.
        """
        return safe_get(self._report_files, 'data', 'attributes', attribute)

    def type_tags(self, *, tag: str = '[type_tags]', **kwargs) -> list[str]:
        data = self._get_attribute_from_report('type_tags')

        if not data:
            return []

        result_iter = map(lambda s: f'{tag} {s}', data)
        return list(result_iter)

    def type_tag(self, *, tag: str = '[type_tag]', **kwargs) -> list[str]:
        data = self._get_attribute_from_report('type_tag')

        if not data:
            return []

        result = f'{tag} {data}'
        return [result]

    def detectiteasy(self, *, tag: str = '[detectiteasy]', **kwargs) -> list[str]:
        data = self._get_attribute_from_report('detectiteasy')

        if not data:
            return []

        filetype = data.get('filetype', '')

        result_iter = map(
            lambda x: ' '.join(
                [
                    filetype,
                    x.get('info', ''),
                    x.get('version', ''),
                    x.get('type', ''),
                    x.get('name', ''),
                ]
            ).strip(),
            data.get('values', [])
        )

        result_iter = map(lambda x: f'{tag} {x}', result_iter)
        return list(result_iter)

    def type_extension(self, *, tag: str = '[type_extension]', **kwargs) -> list[str]:
        data = self._get_attribute_from_report('type_extension')

        if not data:
            return []

        result = f'{tag} {data}'
        return [result]

    def import_list(self, *, tag: str = '[import_list]', **kwargs) -> list[str]:
        data = self._get_attribute_from_report('import_list')

        if not data:
            return []

        result_iters = []

        for lib in data:
            lib_name = lib.get("library_name")
            res_iter = map(
                lambda x: f'{lib_name}: {x}',
                lib.get('imported_functions'),
            )
            result_iters.extend(res_iter)

        result_iter = map(lambda map_: f'{tag} {list(map_)}', result_iters)
        return list(result_iter)

    def magic(self, *, tag: str = '[magic]', **kwargs) -> list[str]:
        data = self._get_attribute_from_report('magic')
        if not data:
            return []

        result = f'{tag} {data}'
        return [result]

    def _get_attribute_from_sandboxes(self, attribute: str):
        report = {}

        for sandbox in self.sandboxes:
            value = safe_get(self._sandbox_reports, sandbox, 'attributes', attribute)
            if value is not None:
                report[sandbox] = value

        return report if report else None

    def mitre_attack_techniques(
            self,
            *,
            tag: str = '[mitre_attack_techniques]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('mitre_attack_techniques')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: f'{x["id"]} {x["signature_description"]}', info)
        result_iter = map(lambda x: f'{tag} {x}', result_iter)
        return list(result_iter)

    def signature_matches(
            self,
            *,
            tag: str = '[signature_matches]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('signature_matches')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox, [])
        if info is None:
            return []

        result_iter = map(lambda x: x.get('description'), info)
        result_iter = filter(lambda x: x is not None, result_iter)
        result_iter = map(lambda x: f'{tag} {x}', result_iter)
        # drop uniques
        return list(set(result_iter))

    def registry_keys_opened(
            self,
            *,
            tag: str = '[registry_keys_opened]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('registry_keys_opened')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox, [])
        if info is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', info)
        return list(result_iter)

    def command_executions(
            self,
            *,
            tag: str = '[command_executions]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('command_executions')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        commands = data.get(sandbox, [])
        if commands is None:
            return []

        result_iter = filter(lambda x: x.strip(), commands)
        result_iter = map(lambda x: f'{tag} {x}', result_iter)
        return list(result_iter)

    def registry_keys_set(
            self,
            *,
            tag: str = '[registry_keys_set]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('registry_keys_set')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: (x.get('key'), x.get('value')), info)
        result_iter = filter(lambda x: None not in x, result_iter)
        result_iter = map(lambda key, value: f"'{key}': '{value}'", result_iter)
        result_iter = map(lambda x: f'{tag} {x}', result_iter)
        return list(result_iter)

    def mutexes_opened(
            self,
            *,
            tag: str = '[mutexes_opened]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('mutexes_opened')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', info)
        return list(result_iter)

    def dns_lookups(
            self,
            *,
            tag: str = '[dns_lookups]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('dns_lookups')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        lookups = data.get(sandbox)
        if lookups is None:
            return []

        result_iter = map(lambda lookup: lookup.get('hostname'), lookups)
        result_iter = filter(lambda hostname: hostname is not None, result_iter)
        result_iter = map(lambda x: f'{tag} {x}', result_iter)
        return list(result_iter)

    def calls_highlighted(
            self,
            *,
            tag: str = '[calls_highlighted]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('calls_highlighted')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', info)
        return list(result_iter)

    def mutexes_created(
            self,
            *,
            tag: str = '[mutexes_created]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('mutexes_created')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', info)
        return list(result_iter)

    @staticmethod
    def _parse_processes_tree(tree):
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

    def processes_tree(
            self,
            *,
            tag: str = '[processes_tree]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('processes_tree')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        tree = data.get(sandbox)
        if tree is None:
            return []

        nodes = self._parse_processes_tree(tree)
        result_iter = map(lambda x: f'{tag} {" -> ".join(x)}', nodes)
        return list(result_iter)

    def modules_loaded(
            self,
            *,
            tag: str = '[modules_loaded]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('modules_loaded')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        modules = data.get(sandbox)
        if modules is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', modules)
        return list(result_iter)

    def processes_created(
            self,
            *,
            tag: str = '[processes_created]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('processes_created')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        processes = data.get(sandbox)
        if processes is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', processes)
        return list(result_iter)

    def files_attribute_changed(
            self,
            *,
            tag: str = '[files_attribute_changed]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('files_attribute_changed')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', info)
        return list(result_iter)

    def registry_keys_deleted(
            self,
            *,
            tag: str = '[registry_keys_deleted]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('registry_keys_deleted')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', info)
        return list(result_iter)

    def services_started(
            self,
            *,
            tag: str = '[services_started]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('services_started')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', info)
        return list(result_iter)

    def ip_traffic(
            self,
            *,
            tag: str = '[ip_traffic]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('ip_traffic')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        traffic = data.get(sandbox)
        if traffic is None:
            return []

        result_iter = map(
            lambda x: ' '.join(
                [
                    str(x.get('transport_layer_protocol', '')),
                    str(x.get('destination_ip', '')),
                    str(x.get('destination_port', '')),
                ]
            ).strip(),
            traffic,
        )
        result_iter = map(lambda x: f'{tag} {x}', result_iter)
        return list(result_iter)

    def processes_terminated(
            self,
            *,
            tag: str = '[processes_terminated]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('processes_terminated')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', info)
        return list(result_iter)

    def files_deleted(
            self,
            *,
            tag: str = '[files_deleted]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('files_deleted')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        files = data.get(sandbox)
        if files is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', files)
        return list(result_iter)

    def files_dropped(
            self,
            *,
            tag: str = '[files_dropped]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('files_dropped')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        files = data.get(sandbox)
        if files is None:
            return []

        result_iter = map(lambda info: info.get('path'), files)
        result_iter = filter(lambda x: x is not None, result_iter)
        result_iter = map(lambda x: f'{tag} {x}', result_iter)
        return list(result_iter)

    def files_copied(
            self,
            *,
            tag: str = '[files_copied]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('files_copied')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        files = data.get(sandbox)
        if files is None:
            return []

        result_iter = map(lambda x: f'from {x["source"]} to {x["destination"]}', files)
        result_iter = map(lambda x: f'{tag} {x}', result_iter)
        return list(result_iter)

    def files_written(
            self,
            *,
            tag: str = '[files_written]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('files_written')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        files = data.get(sandbox)
        if files is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', files)
        return list(result_iter)

    def http_conversations(
            self,
            *,
            tag: str = '[http_conversations]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('http_conversations')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: (x.get('request_method'), x.get('url')), info)        
        result_iter = filter(lambda x: None not in x, result_iter)
        result_iter = map(lambda method_url: f'{method_url[0]} {method_url[1]}', result_iter)
        result_iter = map(lambda x: f'{tag} {x}', result_iter)
        return list(result_iter)

    def files_opened(
            self,
            *,
            tag: str = '[files_opened]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('files_opened')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        files = data.get(sandbox)
        if files is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', files)
        return list(result_iter)

    def processes_injected(
            self,
            *,
            tag: str = '[processes_injected]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('processes_injected')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', info)
        return list(result_iter)

    def services_opened(
            self,
            *,
            tag: str = '[services_opened]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('services_opened')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', info)
        return list(result_iter)

    def signals_hooked(
            self,
            *,
            tag: str = '[signals_hooked]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('signals_hooked')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', info)
        return list(result_iter)

    def windows_searched(
            self,
            *,
            tag: str = '[windows_searched]',
            sandbox: Optional[str] = None,
            **kwargs,
    ) -> list[str]:
        data = self._get_attribute_from_sandboxes('windows_searched')

        if not data:
            return []

        if sandbox is None:
            sandbox = self.sandboxes[0]

        info = data.get(sandbox)
        if info is None:
            return []

        result_iter = map(lambda x: f'{tag} {x}', info)
        return list(result_iter)
