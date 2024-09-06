def are_filters_match_response_content(all_filter_arguments: list[tuple[list, str]], api_response: dict) -> bool:
    """
    Verify whether any filter arguments of a command match the api response content.

    Args:
        all_filter_arguments (list[tuple]): pairs of filter arguments inputs & a response key.
        api_response (dict): api response.

    Returns:
        bool: True if in any of the filter arguments there was a match, False otherwise.
    """
    for arguments in all_filter_arguments:
        command_args, resp_key = arguments
        for arg in command_args:
            if arg == api_response.get(resp_key):
                return True
    return False