from tinydb import *
from functions import *
db = TinyDB('db.json')
indicators_table = db.table('indicators')
Indicator= Query()


def insert_indicators_in_table(modified_date, indicator_type):
    """
    Inserts indicators into the database if they do not already exist.

    Parameters:
    modified_date (str): The date when the indicators were modified.
    indicator_type (str): The type of indicators to retrieve.

    Returns:
    None
    """
    # Retrieve full details of indicators based on the modified date and type
    indicators_full_details = get_indicators(modified_date, indicator_type)

    # Get all existing indicators from the database
    found_indicators_in_database = indicators_table.all()
    indicators_found_in_database = []

    # Collect indicators that are currently in the database
    for each in found_indicators_in_database:
        indicators_found_in_database.append(each['indicator'])

    # Loop through the retrieved indicators to check for insertion
    for indicator in indicators_full_details:
        ind = indicator['indicator']
        
        # Check if the indicator is already in the database
        if ind not in indicators_found_in_database:
            # Insert the new indicator into the database
            indicators_table.insert(indicator)
            print('Indicator inserted in database')
        else:
            # Indicate that the indicator already exists
            print('Indicator already exists in database')

insert_indicators_in_table('2024-01-01', 'CVE')