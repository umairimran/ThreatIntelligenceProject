from tinydb import *
from functions import *
from OTXv2 import *
from datetime import datetime, timedelta
db = TinyDB('db.json')
indicators_table = db.table('indicators')
Indicator= Query()
from dotenv import load_dotenv
load_dotenv()
otx_object = OTXv2(os.getenv('os.getenv('"API_KEY"')'))

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
        indicators_found_in_database.append(json_normalize(each)['general.base_indicator.indicator'][0])



    # Loop through the retrieved indicators to check for insertion
    for indicator in indicators_full_details:
        ind = json_normalize(indicator)['general.base_indicator.indicator'][0]
        
        # Check if the indicator is already in the database
        if ind not in indicators_found_in_database:
            # Insert the new indicator into the database
            indicators_table.insert(indicator)
            print('Indicator inserted in database')
        else:
            # Indicate that the indicator already exists
            print('Indicator already exists in database')

def search_for_indicator(query):
    """
    Searches for an indicator in the database based on a query.

    Parameters:
    query (str): The query to search for in the database.

    Returns:
    list: A list of dictionaries containing the search results. in raw form 
    """

    pattern = re.compile(query, re.IGNORECASE)  # Case-insensitive regex pattern
    results = []
 
    for doc in indicators_table.all():

        df=json_normalize(doc)
        try:
            description = df['general.description'][0]
        except KeyError:
            description = ''
        # Check if the pattern matches the description field
        if pattern.search(str(description)):
            results.append(doc)
    return results

def get_cleaned_indicator_data_from_database(query):
    ''''
    This function takes input as query and searches by using the search for indicator function and then returns the cleaned data in the form of a dataframe

    return : dataframe on each row is a complete indicator full details of a whole section
    '''
    raw_indicators=search_for_indicator(query)
    df=json_normalize(raw_indicators)
    return df
    

def get_single_indicator_full_details(data):
    df=json_normalize(data)


def refresh():
    """
    Refreshes the database by removing all existing data.

    Parameters:
    None

    Returns:
    None
    """
    insert_indicators_in_table((datetime.now() - timedelta(days=1)).date(), 'CVE')
