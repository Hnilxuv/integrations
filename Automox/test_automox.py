import unittest
from unittest.mock import patch, MagicMock

import requests
from requests import HTTPError

import orenctl
from Automox import list_devices, list_organizations, action_on_vulnerability_sync_batchs, \
    action_on_vulnerability_sync_tasks, get_vulnerability_sync_batchs, list_vulnerability_sync_batches, \
    list_vulnerability_sync_tasks, list_policies, update_devices, list_groups, create_groups, update_groups, \
    delete_groups, remove_key, get_default_server_group_id, Automox


def mock_getArg_side_effect(key):
    return {
        'ORG_IDENTIFIER': '123',
        'DEVICE_IDENTIFIER': '444',
        'DEFAULT_ORG_ID': '111',
        'batch_id': '1234',
        'task_id': '222',
        'server_group_id': '333',
        'status': True,
        'action': 'test',
        'group_id': '555',
        'limit': '100',
        'page': '1',
        'name': 'name_test',
        'refresh_interval': '12',
        'parent_server_group_id': '312',
        'policies': '3112',
    }.get(key)


class TestAutoMox(unittest.TestCase):

    def setUp(self):
        self.client = MagicMock()
        self.org_id = 'org_123'

    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_list_device_success(self, mock_automox, mock_results):
        mock_instance = mock_automox.return_value
        orenctl.set_input_args({
            "org_id": 1,
            "group_id": 2,
            "limit": 100,
            "page": 1,
        })
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

    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_list_organizations_success(self, mock_automox, mock_results):
        mock_instance = mock_automox.return_value
        mock_instance.list_organization.return_value = [
            {
                'id': 'org1',
                'name': 'Organization 1',
                'addr1': '123 Street',
                'billing_email': 'contact@example.com',
                'other_key': 'some_value'
            }
        ]
        orenctl.set_input_args({
            "limit": 100,
            "page": 1,
        })

        list_organizations()
        res = orenctl.get_results()

        self.assertIsNotNone(res)

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_action_on_vulnerability_sync_batchs_success(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.action_on_vulnerability_sync_batch.return_value = {
            "mark_as_note": True,
            "readable_output": "Action: test successfully performed on Automox batch ID: 1234"
        }

        action_on_vulnerability_sync_batchs()

        mock_results.assert_called_once_with({
            "mark_as_note": True,
            "readable_output": "Action: test successfully performed on Automox batch ID: 1234"
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_action_on_vulnerability_sync_task_success(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.action_on_vulnerability_sync_task.return_value = {
            "mark_as_note": True,
            "readable_output": "Action: test successfully performed on Automox batch ID: 222"
        }

        action_on_vulnerability_sync_tasks()

        mock_results.assert_called_once_with({
            "mark_as_note": True,
            "readable_output": "Action: test successfully performed on Automox task ID: 222"
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_get_vulnerability_sync_batchs_success(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.get_vulnerability_sync_batch.return_value = 200

        get_vulnerability_sync_batchs()

        mock_results.assert_called_once_with({
            "outputs_prefix": "Automox.VulnSyncBatch",
            "outputs_key_field": 'id',
            "outputs": 200
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_list_vulnerability_sync_batches_success(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.list_vulnerability_sync_batche.return_value = 200

        list_vulnerability_sync_batches()

        mock_results.assert_called_once_with({
            "outputs_prefix": "Automox.VulnSyncBatches",
            "outputs_key_field": "id",
            "outputs": 200
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_list_vulnerability_sync_tasks_fail(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.list_vulnerability_sync_task.return_value = [
            ValueError("Key 'partner_user_id' not found in Automox response.")]

        list_vulnerability_sync_tasks()

        called_args = mock_results.call_args[0][0]

        self.assertEqual(called_args['outputs_prefix'], 'Automox.VulnSyncTasks')
        self.assertEqual(called_args['outputs_key_field'], 'id')

        actual_error_msg = str(called_args['outputs'][0])
        expected_error_msg = "Key 'partner_user_id' not found in Automox response."
        self.assertEqual(actual_error_msg, expected_error_msg)

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_list_policies_fail(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.list_policie.return_value = [
            ValueError("Key 'schedule_time' not found in Automox response.")]

        list_policies()

        called_args = mock_results.call_args[0][0]

        self.assertEqual(called_args['outputs_prefix'], 'Automox.Policies')
        self.assertEqual(called_args['outputs_key_field'], 'id')

        actual_error_msg = str(called_args['outputs'][0])
        expected_error_msg = "Key 'schedule_time' not found in Automox response."
        self.assertEqual(actual_error_msg, expected_error_msg)

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_update_devices_success(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.update_device.return_value = 200

        update_devices()

        mock_results.assert_called_once_with({
            "mark_as_note": True,
            "readable_output": "Device: None successfully updated in Automox"
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_create_group_success(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.create_group.return_value = 200

        create_groups()

        mock_results.assert_called_once_with({
            "outputs_prefix": "Automox.CreatedGroups",
            "outputs_key_field": "id",
            "outputs": 200
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_cupdate_groups_success(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.update_group.return_value = 200

        update_groups()

        mock_results.assert_called_once_with({
            "mark_as_note": True,
            "readable_output": "Group: 555 (name_test) successfully updated in Automox."
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('Automox.Automox')
    def test_delete_groups_success(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.delete_group.return_value = 200

        delete_groups()

        mock_results.assert_called_once_with({
            "outputs_prefix": "Automox.Groups",
            "outputs_key_field": "id",
            "outputs": {
                "id": "555",
                "deleted": True,
            },
            "mark_as_note": True,
            "readable_output": "Group: 555 successfully deleted from Automox"
        })

    def test_remove_existing_key(self):
        data = {
            'a': {
                'b': {
                    'c': 'value'
                }
            }
        }
        keys = ['a', 'b', 'c']
        expected = {'a': {'b': {}}}
        result = remove_key(keys, data)
        self.assertEqual(result, expected)

    def test_remove_key_from_list(self):
        data = {
            'a': [
                {'b': 'value1'},
                {'b': 'value2'}
            ]
        }
        keys = ['a', 'b']
        expected = {'a': [{} for _ in range(2)]}
        result = remove_key(keys, data)
        self.assertEqual(result, expected)

    def test_remove_key_from_nested_list(self):
        data = {
            'a': [
                {'b': {'c': 'value1'}},
                {'b': {'c': 'value2'}}
            ]
        }
        keys = ['a', 'b', 'c']
        expected = {'a': [{'b': {}}, {'b': {}}]}
        result = remove_key(keys, data)
        self.assertEqual(result, expected)

    def test_default_server_group_found(self):
        self.client.list_group.side_effect = [
            [{'id': 'group_1', 'name': 'Group 1'}, {'id': 'group_2', 'name': None}],
            [{'id': 'group_3', 'name': 'Group 3'}]
        ]

        result = get_default_server_group_id(self.client, self.org_id)

        self.assertEqual(result, 'group_2')
        self.client.list_group.assert_called()

    @patch('orenctl.getParam')
    def test_initialization(self, mock_getParam):
        mock_getParam.side_effect = lambda param: {
            'url': 'http://example.com',
            'insecure': 'true',
            'api_key': 'test_api_key',
            'proxy': 'http://proxy.example.com'
        }.get(param)

        automox = Automox()

        # Assert that the parameters are set correctly
        self.assertEqual(automox.url, 'http://example.com')
        self.assertTrue(automox.insecure)
        self.assertEqual(automox.api_key, 'test_api_key')
        self.assertEqual(automox.proxy, 'http://proxy.example.com')
        self.assertIsInstance(automox.session, requests.Session)

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_success(self, mock_request, mock_getParam):
        mock_getParam.return_value = 'http://example.com'
        mock_request.return_value = MagicMock(status_code=200, content=b'{"key": "value"}')
        mock_request.return_value.json.return_value = {"key": "value"}

        automox = Automox()

        result = automox.http_request('GET', '/test_url')

        # Assert the result is as expected
        self.assertEqual(result, {"key": "value"})
        mock_request.assert_called_once_with(
            method='GET',
            url='http://example.com/test_url',
            verify=False
        )

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_failure(self, mock_request, mock_getParam):
        mock_getParam.return_value = 'http://example.com'
        mock_request.return_value = MagicMock(status_code=500, content=b'Error')

        automox = Automox()

        with self.assertRaises(HTTPError):
            automox.http_request('GET', '/test_url')

    @patch('Automox.Automox.http_request')
    def test_get_list_results(self, mock_http_request):
        mock_http_request.side_effect = [
            {'data': [{'item': 1}, {'item': '2'}]},
            {'data': [{'item': 3}, {'item': '4'}]},
            {'data': [{'item': '5'}]}]

        instance = Automox()

        params = {'limit': 2, 'page': 1}

        results = instance.get_list_results('GET', '/test_url', params)

        expected_results = [{'item': 1}, {'item': '2'}]

        self.assertEqual(results, expected_results)

    @patch('Automox.Automox.get_list_results')
    def test_list_device(self, mock_get_list_results):
        mock_get_list_results.return_value = [
            {'id': 'device1', 'name': 'Device 1'},
            {'id': 'device2', 'name': 'Device 2'}
        ]

        instance = Automox()

        org_id = 'org_123'
        group_id = 'group_456'
        limit = 10
        page = 1

        results = instance.list_device(org_id, group_id, limit, page)

        expected_results = [
            {'id': 'device1', 'name': 'Device 1'},
            {'id': 'device2', 'name': 'Device 2'}
        ]

        self.assertEqual(results, expected_results)

    @patch('Automox.Automox.get_list_results')
    def test_list_organization(self, mock_get_list_results):
        mock_get_list_results.return_value = [
            {'id': 'org1', 'name': 'Organization 1'},
            {'id': 'org2', 'name': 'Organization 2'}
        ]

        instance = Automox()

        limit = 10
        page = 1

        results = instance.list_organization(limit, page)

        expected_results = [
            {'id': 'org1', 'name': 'Organization 1'},
            {'id': 'org2', 'name': 'Organization 2'}
        ]

        self.assertEqual(results, expected_results)

    @patch('Automox.Automox.http_request')
    def test_action_on_vulnerability_sync_batch_accept(self, mock_http_request):
        mock_http_request.return_value = {"status": "success", "action": "accept"}

        instance = Automox()

        org_id = "org_123"
        batch_id = "batch_456"
        action = "accept"

        result = instance.action_on_vulnerability_sync_batch(org_id, batch_id, action)

        expected_result = {"status": "success", "action": "accept"}

        self.assertEqual(result, expected_result)