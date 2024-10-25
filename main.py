## Imports For Flask Application
from flask import Flask
from flask import request
from flask import redirect
from flask import render_template
import os
from admin import *
from flask_caching import Cache
# Configure the cache

from flask import url_for,flash
from flask import Flask, render_template, request, redirect, flash, session
from flask import session
from functions import *
from tinyDb import *

app=Flask(__name__)
# Flag to control session clearing
clear_session_flag = True
cache = Cache(app, config={'CACHE_TYPE': 'simple'})
app.secret_key = '123456789'
# Create the users table when the app starts
users = retrieve_users() 


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        print(username, password)
        
        # Create a dictionary for easy user lookup
        user_dict = {user[1]: user[2] for user in users}  # user[1] is username, user[2] is password
        
        print(user_dict)  # Debug print to check user credentials

        # Validate credentials
        if username in user_dict and user_dict[username] == password:
            session['username'] = username  # Store username in session
            flash('Login successful!', 'success')
            return redirect(url_for('search_indicators'))  # Redirect to the search indicators page
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('login.html')  # Render login form if GET request
@app.route('/')
def index():
    global clear_session_flag
    if  clear_session_flag:
        session.clear()
        clear_session_flag=False
    if 'username' in session:  # Check if the user is logged in
        print("Logged in")
        return redirect(url_for('search_indicators'))  # Redirect to search_indicators if logged in
    else:
        return redirect(url_for('login'))  # Redirect to login if not logged in
@app.route('/pulses',methods=['GET','POST'])
def pulses():
    if request.method == 'POST':
        print("Inside pulses post")
        query = request.form['search_query']
        pulses=get_pulses(query,100)
        return render_template('pulses.html',pulses=pulses)
    ## At This Point when the user profiling thing will come we would a
    # addd the user setted env from the database and then we will search to make feed customizes
    query="malware"
    pulses=get_pulses(query,100)
    return render_template('pulses.html',pulses=pulses)

@app.route('/get_pulse_full_detail',methods=['GET','POST'])
def get_pulse_full_detail():
    if request.method == 'POST':
        pulse_id = request.form['id']
        pulse_details = get_pulse_detail(pulse_id)
        pulse_indicators = get_pulse_indicators(pulse_id)
        return render_template('pulse_detail.html',pulse_details=pulse_details, pulse_indicators=pulse_indicators)

@app.route('/single_indicator', methods=['GET', 'POST'])
def single_indicator():
    if request.method == 'POST':
        indicator_type = request.form['indicator_type']
        pulse_id= request.form['indicator_name']
        indicator_number = request.form['indicator_number']
        print(indicator_type,pulse_id, indicator_number),
        pulse_indicators=get_pulse_indicators(pulse_id)
    
        print("_______________________________________\n")
        matched_indicator_type = get_indicator_type(indicator_type)
       
        i=otx_object.get_indicator_details_full(DOMAIN, "aadvanced-ip-scanner.com")
        i=json_normalize(i)
        single_indicator={}
        single_indicator['urls'] = int(i['url_list.limit'][0])
        single_indicator['dns_count'] =int(i['passive_dns.count'][0])
        single_indicator['id'] = int(i['general.base_indicator.id'][0])
        single_indicator['country'] = i['geo.flag_title'][0]
        single_indicator['indicator'] = i['general.base_indicator.indicator'][0]
        single_indicator['type'] = i['general.base_indicator.type'][0]
        single_indicator['asn'] = i['geo.asn'][0]
        single_indicator['access_type'] = i['general.base_indicator.access_type'][0]
        single_indicator['continent_code'] = i['geo.continent_code'][0]
        single_indicator['external_link_1'] =i['general.whois'][0]
        single_indicator['external_link_2'] = i['general.alexa'][0]

        url_list_data = i["url_list.url_list"][0]
    
        ii = json_normalize(url_list_data)  # Normalize if data is present
        urls_list = get_urls_list_of_indicator(ii)
        
        passive_dns_data = i["passive_dns.passive_dns"][0]
           
        passive_dns_df = json_normalize(passive_dns_data)  # Normalize if data is present
        passive_dns_list = get_passive_dns_list_of_indicator(passive_dns_df)
        print("Single Indicator",single_indicator)
        print("URLS",urls_list)
        print("PASSIVE DNS",passive_dns_list)
        return render_template('single_indicators_details.html', single_indicator=single_indicator,urls_list=urls_list,passive_dns_list=passive_dns_list)
     
    return render_template('single_indicators_details.html',single_indicator=[],urls_list=[],passive_dns_list=[])

@app.route('/cve', methods=['GET', 'POST'])
def cve_page():
    if request.method == 'POST':
        indicator_type=request.form['base_indicator_type']
        indicator=request.form['indicator']
        """
        In this function, we will get the query-based results,
        but here just for page demo, doing this.
        This will appear after the page that will have all 
        the list of indicators. When a user clicks on one, 
        it will open a page and get the indicator from the cache
        of the session and pass its info to the page.
        """
        i = otx_object.get_indicator_details_full(indicator_type=get_indicator_type(indicator_type), indicator=indicator)
        df = json_normalize(i)

        # Define a helper function to safely get values from the DataFrame
        def safe_get(column_name):
            return df[column_name][0] if column_name in df.columns else ''

        general_sections = safe_get('general.sections')
        general_mitre_url = safe_get('general.mitre_url')
        general_nvd_url = safe_get('general.nvd_url')
        general_indicator = safe_get('general.indicator')
        general_type_title = safe_get('general.type_title')
        general_base_indicator_id = int(safe_get('general.base_indicator.id')) if safe_get('general.base_indicator.id') else 0
        general_base_indicator_type = safe_get('general.base_indicator.type')
        general_pulse_info_count = safe_get('general.pulse_info.count')
        general_pulse_info_pulses = safe_get('general.pulse_info.pulses')
        general_pulse_info_references = safe_get('general.pulse_info.references')
        general_pulse_info_related_alienvault_malware_families = safe_get('general.pulse_info.related.alienvault.malware_families')
        general_pulse_info_related_alienvault_industries = safe_get('general.pulse_info.related.alienvault.industries')
        general_pulse_info_related_other_adversary = safe_get('general.pulse_info.related.other.adversary')
        general_pulse_info_related_other_malware_families = safe_get('general.pulse_info.related.other.malware_families')
        general_pulse_info_related_other_industries = safe_get('general.pulse_info.related.other.industries')
        general_false_positive = safe_get('general.false_positive')
        general_cve = safe_get('general.cve')
        general_cvss_access_complexity = safe_get('general.cvss.Access-Complexity')
        general_cvss_access_vector = safe_get('general.cvss.Access-Vector')
        general_cvss_authentication = safe_get('general.cvss.Authentication')
        general_cvss_availability_impact = safe_get('general.cvss.Availability-Impact')
        general_cvss_score = safe_get('general.cvss.Score')
        general_cvss_confidentiality_impact = safe_get('general.cvss.Confidentiality-Impact')
        general_cvss_integrity_impact = safe_get('general.cvss.Integrity-Impact')
        general_cvss_vector_string = safe_get('general.cvss.vectorString')
        general_cvssv2_ac_insuf_info = safe_get('general.cvssv2.acInsufInfo')
        general_cvssv2_access_complexity = safe_get('general.cvssv2.cvssV2.accessComplexity')
        general_cvssv2_access_vector = safe_get('general.cvssv2.cvssV2.accessVector')
        general_cvssv2_authentication = safe_get('general.cvssv2.cvssV2.authentication')
        general_cvssv2_availability_impact = safe_get('general.cvssv2.cvssV2.availabilityImpact')
        general_cvssv2_base_score = safe_get('general.cvssv2.cvssV2.baseScore')
        general_cvssv2_confidentiality_impact = safe_get('general.cvssv2.cvssV2.confidentialityImpact')
        general_cvssv2_integrity_impact = safe_get('general.cvssv2.cvssV2.integrityImpact')
        general_cvssv2_version = safe_get('general.cvssv2.cvssV2.version')
        general_cvssv2_exploitability_score = safe_get('general.cvssv2.exploitabilityScore')
        general_cvssv2_impact_score = safe_get('general.cvssv2.impactScore')
        general_cvssv2_obtain_all_privilege = safe_get('general.cvssv2.obtainAllPrivilege')
        general_cvssv2_obtain_other_privilege = safe_get('general.cvssv2.obtainOtherPrivilege')
        general_cvssv2_obtain_user_privilege = safe_get('general.cvssv2.obtainUserPrivilege')
        general_cvssv2_severity = safe_get('general.cvssv2.severity')
        general_cvssv2_user_interaction_required = safe_get('general.cvssv2.userInteractionRequired')
        general_cvssv3_attack_complexity = safe_get('general.cvssv3.cvssV3.attackComplexity')
        general_cvssv3_attack_vector = safe_get('general.cvssv3.cvssV3.attackVector')
        general_cvssv3_availability_impact = safe_get('general.cvssv3.cvssV3.availabilityImpact')
        general_cvssv3_base_score = safe_get('general.cvssv3.cvssV3.baseScore')
        general_cvssv3_base_severity = safe_get('general.cvssv3.cvssV3.baseSeverity')
        general_cvssv3_confidentiality_impact = safe_get('general.cvssv3.cvssV3.confidentialityImpact')
        general_cvssv3_integrity_impact = safe_get('general.cvssv3.cvssV3.integrityImpact')
        general_cvssv3_privileges_required = safe_get('general.cvssv3.cvssV3.privilegesRequired')
        general_cvssv3_scope = safe_get('general.cvssv3.cvssV3.scope')
        general_cvssv3_user_interaction = safe_get('general.cvssv3.cvssV3.userInteraction')
        general_cvssv3_version = safe_get('general.cvssv3.cvssV3.version')
        general_cvssv3_exploitability_score = safe_get('general.cvssv3.exploitabilityScore')
        general_cvssv3_impact_score = safe_get('general.cvssv3.impactScore')
        
        general_configurations_cve_data_version = safe_get('general.configurations.CVE_data_version')
       
        df['general.configurations.nodes'][0]
        general_configurations_nodes=[]
        for cpe in df['general.configurations.nodes'][0]:
            general_configurations_nodes.append(cpe['cpe_match'])
            
        general_cwe = safe_get('general.cwe')
        general_products = safe_get('general.products')
        general_seen_wild = safe_get('general.seen_wild')
        general_references = safe_get('general.references')
        general_description = safe_get('general.description')
        general_date_modified = safe_get('general.date_modified')
        general_date_created = safe_get('general.date_created')
        general_exploits = safe_get('general.exploits')
        general_epss = safe_get('general.epss')
        
        return render_template('indicator_full_detail.html', 
                               general_sections=general_sections,
                               general_mitre_url=general_mitre_url,
                               general_nvd_url=general_nvd_url,
                               general_indicator=general_indicator,
                               general_type_title=general_type_title,
                               general_base_indicator_id=general_base_indicator_id,
                               general_base_indicator_type=general_base_indicator_type,
                               general_pulse_info_count=general_pulse_info_count,
                               general_pulse_info_pulses=general_pulse_info_pulses,
                               general_pulse_info_references=general_pulse_info_references,
                               general_pulse_info_related_alienvault_malware_families=general_pulse_info_related_alienvault_malware_families,
                               general_pulse_info_related_alienvault_industries=general_pulse_info_related_alienvault_industries,
                               general_pulse_info_related_other_adversary=general_pulse_info_related_other_adversary,
                               general_pulse_info_related_other_malware_families=general_pulse_info_related_other_malware_families,
                               general_pulse_info_related_other_industries=general_pulse_info_related_other_industries,
                               general_false_positive=general_false_positive,
                               general_cve=general_cve,
                               general_cvss_access_complexity=general_cvss_access_complexity,
                               general_cvss_access_vector=general_cvss_access_vector,
                               general_cvss_authentication=general_cvss_authentication,
                               general_cvss_availability_impact=general_cvss_availability_impact,
                               general_cvss_score=general_cvss_score,
                               general_cvss_confidentiality_impact=general_cvss_confidentiality_impact,
                               general_cvss_integrity_impact=general_cvss_integrity_impact,
                               general_cvss_vector_string=general_cvss_vector_string,
                               general_cvssv2_ac_insuf_info=general_cvssv2_ac_insuf_info,
                               general_cvssv2_access_complexity=general_cvssv2_access_complexity,
                               general_cvssv2_access_vector=general_cvssv2_access_vector,
                               general_cvssv2_authentication=general_cvssv2_authentication,
                               general_cvssv2_availability_impact=general_cvssv2_availability_impact,
                               general_cvssv2_base_score=general_cvssv2_base_score,
                               general_cvssv2_confidentiality_impact=general_cvssv2_confidentiality_impact,
                               general_cvssv2_integrity_impact=general_cvssv2_integrity_impact,
                               general_cvssv2_version=general_cvssv2_version,
                               general_cvssv2_exploitability_score=general_cvssv2_exploitability_score,
                               general_cvssv2_impact_score=general_cvssv2_impact_score,
                               general_cvssv2_obtain_all_privilege=general_cvssv2_obtain_all_privilege,
                               general_cvssv2_obtain_other_privilege=general_cvssv2_obtain_other_privilege,
                               general_cvssv2_obtain_user_privilege=general_cvssv2_obtain_user_privilege,
                               general_cvssv2_severity=general_cvssv2_severity,
                               general_cvssv2_user_interaction_required=general_cvssv2_user_interaction_required,
                               general_cvssv3_attack_complexity=general_cvssv3_attack_complexity,
                               general_cvssv3_attack_vector=general_cvssv3_attack_vector,
                               general_cvssv3_availability_impact=general_cvssv3_availability_impact,
                               general_cvssv3_base_score=general_cvssv3_base_score,
                               general_cvssv3_base_severity=general_cvssv3_base_severity,
                               general_cvssv3_confidentiality_impact=general_cvssv3_confidentiality_impact,
                               general_cvssv3_integrity_impact=general_cvssv3_integrity_impact,
                               general_cvssv3_privileges_required=general_cvssv3_privileges_required,
                               general_cvssv3_scope=general_cvssv3_scope,
                               general_cvssv3_user_interaction=general_cvssv3_user_interaction,
                               general_cvssv3_version=general_cvssv3_version,
                               general_cvssv3_exploitability_score=general_cvssv3_exploitability_score,
                               general_cvssv3_impact_score=general_cvssv3_impact_score,
                               general_configurations_cve_data_version=general_configurations_cve_data_version,
                               general_configurations_nodes=general_configurations_nodes,
                               general_cwe=general_cwe,
                               general_products=general_products,
                               general_seen_wild=general_seen_wild,
                               general_references=general_references,
                               general_description=general_description,
                               general_date_modified=general_date_modified,
                               general_date_created=general_date_created,
                               general_exploits=general_exploits,
                               general_epss=general_epss)

@app.route("/search_indicators", methods=['GET', 'POST'])
def search_indicators():
    query = ""

    if request.method == 'GET':
        # Fetch user settings and show relevant indicators based on those settings
        # Placeholder: get user settings from database (not implemented)
        # Example: user_settings = get_user_settings(user_id)
        query = ""  # Query might be based on user preferences

    if request.method == 'POST':
        # Get the search query from the search form
        query = request.form.get('search_query', '')
        print(f"Received POST request with search query: {query}")
        # You can fetch results from your database and cache them for future requests
        # Example: store the result in cache for future faster access

    # Fetch indicators from cache or database based on query
    indicators_df = get_cleaned_indicator_data_from_database(query)
    indicators_list = []
    indicators_df=indicators_df.head(100)
    # Check if DataFrame is not empty or null
    if indicators_df is not None and not indicators_df.empty:
        # Iterate through each row in the DataFrame
        for index, row in indicators_df.iterrows():
            # Extract specific values from the current row with default fallback values
            indicators_list.append({
                'indicator': row.get('general.base_indicator.indicator', ''),
                'base_indicator_type': row.get('general.base_indicator.type', ''),
                'cvssv2_vulnerability': row.get('general.cvssv2.severity', 'N/A'),
                'cvssv3_attack_complexity': row.get('general.cvssv3.cvssV3.attackComplexity', 'N/A'),
                'cvssv3_base_severity': row.get('general.cvssv3.cvssV3.baseSeverity', 'N/A'),
                'cvssv3_exploitability_score': float(row.get('general.cvssv3.exploitabilityScore', 0.0)),
                'cvssv3_impact_score': float(row.get('general.cvssv3.impactScore', 0.0))
            })

    # Return the indicators to be rendered on the indicators.html template
    return render_template('indicators.html', indicators_list=indicators_list)

@app.route('/test',methods=['GET','POST'])
def test():
    return render_template('indicators.html')

@app.route('/refresh_database',methods=['GET','POST'])
def refresh_database():
    if request.method == 'POST':
        refresh()
        return redirect(url_for('search_indicators'))



@app.route('/admin',methods=['GET','POST'])
def admin_page():
    if request.method=='GET':
        return render_template('admin_dashboard.html')

@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if request.method == 'GET':
        users = retrieve_users() 
    
        return render_template('manage_users.html', users=users)  # Pass users to the template


@app.route('/edit_user', methods=['POST'])
def edit_user_endpoint():
    """Endpoint to edit user details."""
    # Get data from the form
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    system = request.form.get('system')
    service = request.form.get('service')
    indicator = request.form.get('indicator')

    # Check for empty fields and handle accordingly
    if not username or not password or not email or not system or not service or not indicator:
        return "All fields are required.", 400  # Return an error message if any fields are empty

    print(f"Editing user with ID: {user_id}")
    print(f"New details: {username}, {password}, {email}, {system}, {service}, {indicator}")

    # Call the edit_user function
    edit_user(user_id, username, password, email, system, service, indicator)

      # Return a success message

    # Redirect or return a success message
    return redirect(url_for('manage_users'))

@app.route('/delete_user', methods=['POST'])
def delete_user_endpoint():
    """Endpoint to delete a user."""
    # Call the delete_user function
    user_id = request.form.get('user_id')
    print(f"Deleting user with ID: {user_id}")
    delete_user(user_id)

    # Redirect or return a success message
    return redirect(url_for('manage_users'))

@app.route('/create_new_user', methods=['POST'])
def create_user_endpoint():
    """Endpoint to create a new user."""
    # Get data from the form
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    system = request.form.get('system')
    service = request.form.get('service')
    indicator = request.form.get('indicator')

    # Check for required fields
    if not username or not email or not password or not system or not service or not indicator:
        return redirect(url_for('manage_users'))  # Return an error if required fields are empty

    # Call the create_user function
    add_user(username, password, email, system, service, indicator)

    return redirect(url_for('manage_users'))
if __name__ == '__main__':
    app.run(port=5500)