import unittest
from unittest.mock import patch

from Automox import list_devices


def mock_getarg_side_effect(key):
    return {
        "ORG_IDENTIFIER": 'test_org_id',
        "DEVICE_IDENTIFIER": 'test_device_id',
        "GROUP_IDENTIFIER": 'test_group_id',
        "LIMIT_IDENTIFIER": 'test_limit',
        "PAGE_IDENTIFIER": 'test_page'
    }.get(key)


def mock_getparam_side_effect(key):
    return {
        "DEFAULT_ORG_ID ": 'test_org_id',
    }.get(key)


class TestAutoMox(unittest.TestCase):
    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_list_devices(self, mock_automox, mock_results, mock_getArg, mock_getParam):
        mock_instance = mock_automox.return_value
        mock_instance.list_device.return_value = [
            {
                'id': 'device1',
                'name': 'Device 1',
                'compatibility_checks': True,
                'os_version_id': 123,
                'instance_id': 'i-123456',
                'detail': 'some detail',
                'total_count': 10
            }
        ]

        list_devices()
        mock_results.assert_called_once_with({'outputs_prefix': 'Automox.Devices', 'outputs_key_field': 'id',
                                              'outputs': [{'id': 'device1', 'name': 'Device 1'}]})
