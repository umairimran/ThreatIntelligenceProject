## Imports For Flask Application
from flask import Flask
from flask import request
from flask import redirect
from flask import render_template
import os
from flask import url_for,flash
from flask import session
from functions import *

app=Flask(__name__)

def get_default_pulses():
    # Return default pulses data for initial page load
    pass

@app.route('/')
def index():
    return redirect(url_for('pulses'))

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
    pulses=[]
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
if __name__ == '__main__':
    app.run(port=5500)