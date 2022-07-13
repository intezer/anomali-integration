import datetime

import api
import errors
from AnomaliEnrichment import AnomaliEnrichment
from AnomaliEnrichment import CompositeItem
from AnomaliEnrichment import ItemInWidget
from AnomaliEnrichment import ItemTypes
from AnomaliEnrichment import TableWidget
from AnomaliEnrichment import TextWidget
from analysis import FileAnalysis

SEVERITY_TO_NAME = {1: 'low', 2: 'medium', 3: 'high'}
REQUESTER = 'anomali'
MAX_TIMEOUT = 25


def activation(api_key: str):
    api.set_global_api(api_key)
    api.get_global_api().request_with_refresh_expired_access_token('GET', '/accounts/me')


def enrich_hash(ae: AnomaliEnrichment, hash_value: str, wait_timeout: datetime.timedelta, private_only: bool):
    file_analysis = FileAnalysis.from_latest_hash_analysis(hash_value, private_only=private_only, requester=REQUESTER)
    if not file_analysis:
        file_analysis = FileAnalysis(file_hash=hash_value)
        try:
            file_analysis.send(wait=True, wait_timeout=wait_timeout, requester=REQUESTER)
        except errors.HashDoesNotExistError:
            ae.addWidget(TextWidget(ItemInWidget(ItemTypes.String, 'Hash not found in Intezer')))
            return
        except TimeoutError:
            ae.addWidget(TextWidget(ItemInWidget(
                ItemTypes.String,
                'Time out waiting to Intezer result, you can check the result at:'))
            )
            ae.addWidget(TextWidget(ItemInWidget(
                ItemTypes.Link,
                f'https://analyze.intezer.com/analyses/{file_analysis.analysis_id}'))
            )
            return

    analysis_details = file_analysis.result()

    basic_table_widget = TableWidget('Analysis Details', ['Field', 'Value'], columnWidths=['20%', '80%'])

    for key, value in analysis_details.items():
        key_widget = ItemInWidget(ItemTypes.String, key.replace('_', ' ').replace('_', ' ').capitalize())
        if key == 'analysis_url':
            basic_table_widget.addRowOfItems([
                key_widget,
                ItemInWidget(ItemTypes.Link, value, 'View in Intezer Analyze')
            ])
        else:
            basic_table_widget.addRowOfItems([
                key_widget,
                ItemInWidget(ItemTypes.String, value)
            ])

    ae.addWidget(basic_table_widget)

    iocs = file_analysis.iocs
    if iocs:
        if iocs.get('network'):
            network_iocs_table_widget = TableWidget('Network IOCs',
                                                    ['Value', 'Type', 'Source'],
                                                    columnWidths=['70%', '10%', '20%'])

            for ioc in iocs['network']:
                ioc_type = ioc['type']
                type_title = 'IP' if ioc_type == 'ip' else ioc_type.capitalize()
                item_value = item_label = ioc['ioc']
                if ioc_type in ('ip', 'url', 'domain'):
                    item_value = f"detail/v2/{ioc_type}?value={ioc['ioc']}"
                    cell_type = ItemTypes.Link
                else:
                    cell_type = ItemTypes.String
                network_iocs_table_widget.addRowOfItems([ItemInWidget(cell_type, item_value, item_label),
                                                         ItemInWidget(ItemTypes.String, type_title),
                                                         ItemInWidget(ItemTypes.String, ','.join(ioc['source']))])

            ae.addWidget(network_iocs_table_widget)

        if iocs.get('files'):
            files_iocs_table_widget = TableWidget('Files IOCs',
                                                  ['SHA256', 'Path', 'Type', 'Classification'],
                                                  columnWidths=['35%', '45%', '10%', '10%'])
            for file in iocs['files']:
                classification = file['verdict'].capitalize()
                if file.get('family'):
                    classification = f'{classification} ({file["family"]})'
                files_iocs_table_widget.addRowOfItems([
                    ItemInWidget(ItemTypes.Link, f"detail/v2/hash?value={file['sha256']}", file['sha256']),
                    ItemInWidget(ItemTypes.String, file['path']),
                    ItemInWidget(ItemTypes.String, file['type'].replace('_', ' ').capitalize()),
                    ItemInWidget(ItemTypes.String, classification),
                ])

            ae.addWidget(files_iocs_table_widget)

    if file_analysis.dynamic_ttps:
        ttps_table_widget = TableWidget('Signatures',
                                        ['MITRE ATT&CK', 'Technique', 'Severity', 'Details'],
                                        columnWidths=['35%', '30%', '5%', '30%'])
        for ttp in sorted(file_analysis.dynamic_ttps, key=lambda t: t['severity'], reverse=True):
            if 'data' in ttp:
                details_item = CompositeItem(onSeparateLines=True)
                for additional_data in ttp['data']:
                    details_item.addItemInWidget(
                        ItemInWidget(ItemTypes.String,
                                     ','.join(f'{key}:{value}' for key, value in additional_data.items()))
                    )
            else:
                details_item = ItemInWidget(ItemTypes.String, '')

            ttps_table_widget.addRowOfItems([
                ItemInWidget(ItemTypes.String, ttp.get('ttp', {}).get('ttp', '')),
                ItemInWidget(ItemTypes.String, ttp['description']),
                ItemInWidget(ItemTypes.String, SEVERITY_TO_NAME[ttp['severity']].capitalize()),
                details_item
            ])

        ae.addWidget(ttps_table_widget)


def main():
    ae = AnomaliEnrichment()
    ae.parseArguments()

    transform_name = ae.getTransformName()
    entity_value = ae.getEntityValue()

    api_key = ae.getCredentialValue('api_key')
    private_only = ae.getCredentialValue('optional_only_private_analysis')
    if private_only is None:
        private_only = False
    else:
        private_only = private_only.lower()
        if private_only in ['yes', 'true']:
            private_only = True
        elif private_only in ['no', 'false']:
            private_only = False
        else:
            ae.addMessage("ERROR", 'Wrong optional_only_private_analysis format, '
                                   'use one of the following: yes, no, true,false.')
            ae.addException('Input Error : Wrong optional_only_private_analysis format')
            return

    wait_timeout = ae.getCredentialValue('optional_analysis_wait_timeout')
    if wait_timeout:
        try:
            wait_timeout = int(wait_timeout)
            if wait_timeout < 1:
                message = 'Wrong optional_analysis_wait_timeout, must be a positive number'
                ae.addMessage('ERROR', message)
                ae.addException(f'Input Error: {message}')
                return
            elif wait_timeout > MAX_TIMEOUT:
                message = f'Wrong optional_analysis_wait_timeout, must be lower or equal to {MAX_TIMEOUT}'
                ae.addMessage('ERROR', message)
                ae.addException(f'Input Error: {message}')
                return
        except ValueError:
            message = 'Wrong optional_analysis_wait_timeout format, must be a number'
            ae.addMessage('ERROR', message)
            ae.addException(f'Input Error: {message}')
            return
    else:
        wait_timeout = MAX_TIMEOUT

    wait_timeout = datetime.timedelta(seconds=wait_timeout)

    if transform_name is None:
        ae.addException('Transform Name is not provided')

    elif entity_value is None:
        ae.addException('Entity Value is not provided')

    elif api_key is None:
        # Without any calls to addMessage, whatever is given to addException will be shown to the user in the event of
        # an error. Therefore, any errors that can occur during the running of an enrichment should make sure to call
        # addMessage with the "ERROR" parameter to ensure that that is what is shown to the user. Calls to addException
        # should only be used for logging.
        ae.addMessage("ERROR", "No API Key provided.")
        ae.addException('Input Error : Missing API key')
    else:
        api.set_global_api(api_key)
        try:
            if transform_name == 'activation':
                activation(api_key)
            elif transform_name == 'enrichHash':
                try:
                    enrich_hash(ae, entity_value, wait_timeout, private_only)
                except Exception as ex:
                    ae.addException('Unexpected exception : ' + str(ex))
            else:
                ae.addException('Transform Name is unknown : ' + transform_name)
        except Exception as e:
            ae.addMessage("ERROR", "An Unexpected error occurred, please try again. "
                                   "If the error persists please contact support.")
            ae.addException(str(e))

    ae.returnOutput()


if __name__ == '__main__':
    main()
