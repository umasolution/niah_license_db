#!/usr/bin/python3
import email
import os.path
import time
from os import path
import uuid
from flask_jwt_extended import jwt_required, current_user, get_current_user, get_jwt_identity
from authorizenet import apicontractsv1
from authorizenet.apicontrollers import createTransactionController
from flask_jwt_extended import create_access_token
from flask_jwt_extended import JWTManager
from werkzeug.security import safe_str_cmp
import ast
from flask_httpauth import HTTPTokenAuth
from datetime import date, timedelta
from flask import Flask,redirect
from flask import g
from flask_cors import CORS
from werkzeug.utils import secure_filename
import string
import re
from datetime import date
import random
from flask_mail import Mail
from flask_mail import Message
from flask_autoindex import AutoIndex
import datetime
from flask import Flask, render_template, send_from_directory, jsonify, send_file
from flask import Response
from flask import request
import json
import requests
import configparser
import sys
import datetime
import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from flask import make_response
import psycopg2
from jsondiff import diff


mail = Mail()
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
#app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(seconds=3600)
#app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(seconds=3600)
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(seconds=3600)
app.config['SECURITY_PASSWORD_SALT'] = 'my_precious_two'
app.config["SECRET_KEY"] = "super-secret"

jwt = JWTManager(app)
app.config['JWT_TOKEN_LOCATION'] = ["headers"]
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!

CORS(app)

__all__ = ["getstatusoutput","getoutput","getstatus"]

def getstatus(file):
    """Return output of "ls -ld <file>" in a string."""
    import warnings
    warnings.warn("commands.getstatus() is deprecated", DeprecationWarning, 2)
    return getoutput('ls -ld' + mkarg(file))

def getoutput(cmd):
    """Return output (stdout or stderr) of executing cmd in a shell."""
    return getstatusoutput(cmd)[1]

def getstatusoutput(cmd):
    """Return (status, output) of executing cmd in a shell."""
    import os
    pipe = os.popen('{ ' + cmd + '; } 2>&1', 'r')
    text = pipe.read()
    sts = pipe.close()
    if sts is None: sts = 0
    if text[-1:] == '\n': text = text[:-1]
    return sts, text

def mk2arg(head, x):
    import os
    return mkarg(os.path.join(head, x))

def mkarg(x):
    if '\'' not in x:
        return ' \'' + x + '\''
    s = ' "'
    for c in x:
        if c in '\\$"`':
            s = s + '\\'
        s = s + c
    s = s + '"'
    return s


@app.before_request
def db_connect():
    g.conn = psycopg2.connect(user="versa",password="versa123",host="127.0.0.1",port="5432",database="niahdb")
    g.cursor = g.conn.cursor()

@app.after_request
def db_disconnect(response):
    g.cursor.close()
    g.conn.close()
    return response

@app.teardown_appcontext
def close_conn(e):
    db = g.pop('db', None)
    if db is not None:
        app.config['postgreSQL_pool'].putconn(db)

@app.route('/api/userid', methods = ['GET'])
@jwt_required
def getUserID():
    user_id = get_jwt_identity()
    return user_id

def getInvoice():
    query = "select inv_no, name from invoice_tab ORDER BY inv_no DESC LIMIT 1"
    g.cursor.execute(query)
    subDB = g.cursor.fetchall();

    if len(subDB) > 0:
        inv_no = subDB[0][0]
        inv_name = subDB[0][1]

        res = {}
        res['inv_no'] = inv_no
        return res
    else:
        res = {}
        res['inv_no'] = 1
        return res

# API to get subscription detail.
@app.route('/api/get/subscription', methods = ['GET'])
def getSubProfile():
    if request.method == 'GET':
        query = "select subscription_name, scans, users, modules, description from subscription_db"
        g.cursor.execute(query)
        subscribeDB = g.cursor.fetchall();

        results = []
        for pDB in subscribeDB:
            subscription_name = pDB[0]
            scans = pDB[1]
            users = pDB[2]
            modules = pDB[3]
            description = pDB[4]

            modules['scans'] = scans
            modules['users'] = users
            modules['subscription_name'] = subscription_name
            modules['description'] = description
            results.append(modules)

        return jsonify(results)

# API to get subscription data.
@app.route('/api/data/subscription', methods = ['GET'])
def getdataSubscription():
    if request.method == 'GET':
        query = "select type, number, amount from pricing_tab"
        g.cursor.execute(query)
        pricingDB = g.cursor.fetchall();

        results = []
        for pDB in pricingDB:
            stype = pDB[0]
            number = pDB[1]
            amount = pDB[2]
            
            if stype == "subscription":
                query = "select subscription_name from subscription_db where id='%s'" % (number)
                g.cursor.execute(query)
                subscribeDB = g.cursor.fetchall();

                for sDB in subscribeDB:
                    subscription_name = sDB[0]

                    res = {}
                    res['subscription_name'] = subscription_name
                    res['amount'] = amount
                    results.append(res)
            else:
                res = {}
                res['subscription_name'] = "NiahFlexi"

                query = "select numbers, discount from discount_tab where type='%s'" % stype
                g.cursor.execute(query)
                discountDB = g.cursor.fetchall();

                if len(discountDB) > 0:
                    for dDB in discountDB:
                        numbers = dDB[0]
                        discount = dDB[1]

                        res['discount'] = {}
                        res['discount'][stype] = {}
                        res['discount'][stype]['numbers'] = numbers
                        res['discount'][stype]['amount'] = discount

                if stype == "users":
                    res['amount'] = {}
                    res['amount']['users'] = {}
                    res['amount']['users']['number'] = number
                    res['amount']['users']['amount'] = amount

                if stype == "scans":
                    res['amount'] = {}
                    res['amount']['scans'] = {}
                    res['amount']['scans']['number'] = number
                    res['amount']['scans']['amount'] = amount
                
                results.append(res)

        return jsonify(results)


@app.route('/api/get/subscription', methods = ['POST'])
def getSubscription():
    if request.method == 'POST':
        req_data = request.get_json()        
        code = req_data['code']
        emailid = req_data['emailid']

        query = "select subscription, firstname, lastname, companyname, address, city, state, pincode, country, phone, status from subscription_db where emailid='%s' and code='%s'" % (emailid, code)
        g.cursor.execute(query)
        subscribeDB = g.cursor.fetchall();

        if len(subscribeDB) > 0:
            subscription = subscribeDB[0][0]
            firstname = subscribeDB[0][1]
            lastname = subscribeDB[0][2]
            companyname = subscribeDB[0][3]
            address = subscribeDB[0][4]
            city = subscribeDB[0][5]
            state = subscribeDB[0][6]
            pincode = subscribeDB[0][7]
            country = subscribeDB[0][8]
            phone = subscribeDB[0][9]
            status = subscribeDB[0][10]

            res = {}
            res['subscription'] = subscription
            res['firstname'] = firstname
            res['lastname'] = lastname
            res['companyname'] = companyname
            res['address'] = address
            res['city'] = city
            res['state'] = state
            res['pincode'] = pincode
            res['country'] = country
            res['phone'] = phone
            res['status'] = status
        
            return jsonify(res)


def check_license(email_id):
    query = "select status, code, subscription from license_master_db where emailid='%s'" % email_id
    g.cursor.execute(query)
    subscribeDB = g.cursor.fetchall();

    if len(subscribeDB) > 0:
        status = subscribeDB[0][0]
        code = subscribeDB[0][1]
        subscription = subscribeDB[0][2]

        if status == "active":
            res = {}
            res['status'] = status
            res['code'] = code
            res['subscription'] = subscription
            return res
        else:
            res = {}
            res['status'] = status
            res['code'] = code
            res['subscription'] = subscription
            return res
    else:
        return False

# API to subscribe user in niah service.
@app.route('/api/subscription/register', methods = ['POST', 'GET'])
def regSubscription():
    if request.method == 'POST':
        code = "123" # Auto Generate
        req_data = request.get_json()        
        firstname = req_data['firstname']
        lastname = req_data['lastname']
        companyname = req_data['companyname']
        city = req_data['city']
        state = req_data['state']
        pincode = req_data['pincode']
        phone = req_data['phone']
        country = req_data['country']
        emailid = req_data['emailid']
        address = req_data['address']

        subscription = req_data['subscription']

        if subscription == "Free":
            res_sub = check_license(emailid)
            
            if res_sub:
                res = {}
                res['code'] = res_sub['code']
                res['subscription'] =  res_sub['subscription']
                if res_sub['status'] == "active":
                    res['status'] = 1
                    res['message'] = "Subscription found activated"
                else:
                    res['status'] = 0
                    res['message'] = "Subscription Found deactivated"
            else:
                query = "insert into license_master_db(subscription, firstname, lastname, companyname, address, city, state, pincode, country, emailid, phone, code, status) values('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 'active');" % (subscription, firstname, lastname, companyname, address, city, state, pincode, country, emailid, phone, code)
                print(query)
                g.cursor.execute(query)
                g.conn.commit()

                res = {}
                res['status'] = 1
                res['code'] = code
                res['subscription'] = subscription
                res['message'] = "Free Subscription Successfully Activated"
        else:
            amount = req_data['amount']
            cardnumber = req_data['cardnumber']
            expiredate = req_data['expiredate']
            
            exp_year = ''
            exp_month = ''

            if re.findall(r'(\d+)-', str(expiredate)):
                exp_year = re.findall(r'(\d+)-', str(expiredate))[0]
            if re.findall(r'-(\d+)', str(expiredate)):
                exp_month = re.findall(r'-(\d+)', str(expiredate))[0]

            if exp_month and exp_year:
                expiredate = "%s%s" % (exp_month, exp_year)

            cardcodeno = req_data['cardcodeno']
            subscription = req_data['subscription']

            todays_date = date.today()
            yearno = todays_date.year

            inv_details = getInvoice()
            inv_no = inv_details['inv_no'] + 1
            inv_name = "%s-%s" % (yearno, inv_no)

            # Create a merchantAuthenticationType object with authentication details
            # retrieved from the constants file
            merchantAuth = apicontractsv1.merchantAuthenticationType()
            merchantAuth.name = '752nCEHRj5'
            merchantAuth.transactionKey = '926sp4uzACA2UL4h'
            # Create the payment data for a credit card
            creditCard = apicontractsv1.creditCardType()
            creditCard.cardNumber = '%s' % cardnumber
            creditCard.expirationDate = '%s' % expiredate
            creditCard.cardCode = "%s" % cardcodeno
            # Add the payment data to a paymentType object
            payment = apicontractsv1.paymentType()
            payment.creditCard = creditCard

            # Create order information
            order = apicontractsv1.orderType()
            order.invoiceNumber = '%s' % inv_name
            order.description = '%s subscription payment' % subscription

            # Set the customer's Bill To address
            customerAddress = apicontractsv1.customerAddressType()
            customerAddress.firstName = "%s" % firstname
            customerAddress.lastName = "%s" % lastname
            customerAddress.company = "%s" % companyname
            customerAddress.address = "%s" % address
            customerAddress.city = "%s" % city
            customerAddress.state = "%s" % state
            customerAddress.zip = "%s" % pincode
            customerAddress.country = "%s" % country

            # Set the customer's identifying information
            customerData = apicontractsv1.customerDataType()
            customerData.type = "individual"
            customerData.id = "%sC%s" % (subscription, code)
            customerData.email = "%s" % emailid

            # Add values for transaction settings
            duplicateWindowSetting = apicontractsv1.settingType()
            duplicateWindowSetting.settingName = "duplicateWindow"
            duplicateWindowSetting.settingValue = "600"
            settings = apicontractsv1.ArrayOfSetting()
            settings.setting.append(duplicateWindowSetting)

            # setup individual line items
            line_item_1 = apicontractsv1.lineItemType()
            line_item_1.itemId = "%sC%s" % (subscription, code)
            line_item_1.name = "%s" % subscription
            line_item_1.description = "%s subscription with %s code" % (subscription, code)
            line_item_1.quantity = "1"
            line_item_1.unitPrice = amount

            # build the array of line items
            line_items = apicontractsv1.ArrayOfLineItem()
            line_items.lineItem.append(line_item_1)

            # Create a transactionRequestType object and add the previous objects to it.
            transactionrequest = apicontractsv1.transactionRequestType()
            transactionrequest.transactionType = "authCaptureTransaction"
            transactionrequest.amount = amount
            transactionrequest.payment = payment
            transactionrequest.order = order
            transactionrequest.billTo = customerAddress
            transactionrequest.customer = customerData
            transactionrequest.transactionSettings = settings
            transactionrequest.lineItems = line_items

            # Assemble the complete transaction request
            createtransactionrequest = apicontractsv1.createTransactionRequest()
            createtransactionrequest.merchantAuthentication = merchantAuth
            createtransactionrequest.refId = "MerchantID-0001"
            createtransactionrequest.transactionRequest = transactionrequest
            # Create the controller
            createtransactioncontroller = createTransactionController(
                createtransactionrequest)
            createtransactioncontroller.execute()

            response = createtransactioncontroller.getresponse()

            if response is not None:
                # Check to see if the API request was successfully received and acted upon
                if response.messages.resultCode == "Ok":
                    # Since the API request was successful, look for a transaction response
                    # and parse it to display the results of authorizing the card
                    if hasattr(response.transactionResponse, 'messages') is True:
                        print(
                            'Successfully created transaction with Transaction ID: %s'
                            % response.transactionResponse.transId)
                        print('Transaction Response Code: %s' %
                            response.transactionResponse.responseCode)
                        print('Message Code: %s' %
                            response.transactionResponse.messages.message[0].code)
                        print('Description: %s' % response.transactionResponse.
                            messages.message[0].description)

                        # Create Users
                        query = "insert into invoice_tab(inv_no, name, yearno, amount, subscription, firstname, lastname, companyname, address, city, state, pincode, country, emailid, users, scans) values('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s');" % (inv_no, inv_name, yearno, amount, subscription, firstname, lastname, companyname, address, city, state, pincode, country, emailid, '0', '0')
                        print(query)
                        g.cursor.execute(query)
                        g.conn.commit()

                        res_sub = check_license(emailid)
                        if res_sub:
                            query = "update license_master_db set subscription='%s', code='%s', status='active' where emailid='%s'" % (subscription, code, emailid) 
                            print(query)
                            g.cursor.execute(query)
                            g.conn.commit()
                        else:
                            query = "insert into license_master_db(subscription, firstname, lastname, companyname, address, city, state, pincode, country, emailid, phone, code, status) values('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 'active');" % (subscription, firstname, lastname, companyname, address, city, state, pincode, country, emailid, phone, code)
                            print(query)
                            g.cursor.execute(query)
                            g.conn.commit()

                        res = {}
                        res['status'] = 1
                        res['code'] = code
                        res['subscription'] = subscription
                        res['message'] = "Transaction Successfully Completed"
                    else:
                        print('Failed Transaction.')
                        if hasattr(response.transactionResponse, 'errors') is True:
                            print('Error Code:  %s' % str(response.transactionResponse.
                                                        errors.error[0].errorCode))
                            print(
                                'Error message: %s' %
                                response.transactionResponse.errors.error[0].errorText)

                        # Response failed transaction
                        res = {}
                        res['status'] = 0
                        res['message'] = "Transaction Failed"

                # Or, print errors if the API request wasn't successful
                else:
                    print('Failed Transaction.')
                    if hasattr(response, 'transactionResponse') is True and hasattr(
                            response.transactionResponse, 'errors') is True:
                        print('Error Code: %s' % str(
                            response.transactionResponse.errors.error[0].errorCode))
                        print('Error message: %s' %
                            response.transactionResponse.errors.error[0].errorText)
                    else:
                        print('Error Code: %s' %
                            response.messages.message[0]['code'].text)
                        print('Error message: %s' %
                            response.messages.message[0]['text'].text)

                    # Response failed transation
                    res = {}
                    res['status'] = 0
                    res['message'] = "Transaction Failed"

            else:
                res = {}
                res['status'] = 0
                res['message'] = "No Transaction"
                print('Null Response.')

        return jsonify(res)

@app.route('/api/get/license', methods = ['POST'])
@jwt_required
def updateSubCodeUpdate():
    user_id = get_jwt_identity()
    if request.method == 'POST':
        req_data = request.get_json()
        email_add = req_data['emailid']
        code = req_data['code']

        
        query = "select subscription, users, scans, code, status from license_master_db where emailid='%s' and code='%s'" % (email_add, code)
        g.cursor.execute(query)
        fetchData = g.cursor.fetchall()
        
        subscription = fetchData[0][0]
        users = fetchData[0][1]
        scans = fetchData[0][2]
        code = fetchData[0][3]
        status = fetchData[0][4]

        res = {}
        res['subscription'] = subscription
        res['users'] = users
        res['scans'] = scans
        res['code'] = code
        res['status'] = status

        return jsonify(res)

@app.route('/api/feed/update', methods = ['POST'])
def feedUpdate():
    if request.method == 'POST':
        req_data = request.get_json()
        code = req_data['code']
        feed_version = req_data['current_feed_version']

        query = "select version from feed_master_tab where pub_date='current'"
        print(query)
        g.cursor.execute(query)
        current_feed_data = g.cursor.fetchall()

        current_available_feed_version = current_feed_data[0][0]

        if feed_version == current_available_feed_version:
            res = {}
            res['message'] = "No update available"
            return jsonify(res)
        else:
            query = "select status from license_master_db where code='%s'" % code
            print(query)
            g.cursor.execute(query)
            history_data = g.cursor.fetchall()

            if len(history_data) > 0:
                if history_data[0][0] == "enable":
                    res = {}
                    res['current_available_feed_version'] = current_available_feed_version
                    res['message'] = "Current available feed version %s" % current_available_feed_version
                    return jsonify(res)
                else:
                    res = {}
                    res['message'] = "Licence is expired, please check"
                    return jsonify(res)
            else:
                res = {}
                res['message'] = "Licence is not found, please check"
                return jsonify(res)

# API to get vulnerabilities details for specified filters.
@app.route('/api/vuln/list', methods=["GET"])
#@jwt_required
def getdata():
    print("1 - %s" % request.args)
    if 'email_id' in request.args and 'code' in request.args:
        email_id = request.args.get('email_id')
        code = request.args.get('code')
    else:
        res = {}
        res['error'] = 1
        return jsonify(res)

    query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
    print(query)
    g.cursor.execute(query)
    status_data = g.cursor.fetchall()
    
    if len(status_data) > 0:
        if status_data[0][0] == "active":
            if request.args.get('type'):
                type = request.args.get('type')
            else:
                type = ''
            if request.args.get('product'):
                application = request.args.get('product')
            else:
                application = ''
            if request.args.get('productname'):
                product = request.args.get('productname')
            else:
                product = ''
            if request.args.get('vendorname'):
                vendor = request.args.get('vendorname')
            else:
                vendor = ''
            if request.args.get('severity'):
                severity = request.args.get('severity')
                severity = severity.upper()
            else:
                severity = ''
            if request.args.get('attackVector'):
                attackvector = request.args.get('attackVector')
                attackvector = attackvector.upper()
            else:
                attackvector = ''
            if request.args.get('cwe_text'):
                cwe_text = request.args.get('cwe_text')
                cwe_text = cwe_text.upper()
            else:
                cwe_text = ''
            if request.args.get('basescore'):
                basescore = request.args.get('basescore')
            else:
                basescore = ''

            if request.args.get('offset'):
                pageoffset = request.args.get('offset')
                if request.args.get('limit'):
                    rowlimit = request.args.get('limit')
                else:
                    rowlimit = 50
            else:
                pageoffset = 0
                rowlimit = 50
                
            rowlimit = int(pageoffset) + int(rowlimit)

            results = {}

            if type == "plugin":
                results['results'] = []
                results['columns'] = []

                rescol = {}
                rescol['title'] = "Vulnerability"
                rescol['field'] = "vulnerability"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "CWEID"
                rescol['field'] = "cwe_text"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "Severity"
                rescol['field'] = "baseseverity"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "baseScore"
                rescol['field'] = "basescore"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "Attack Vector"
                rescol['field'] = "attackvector"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "PublishDate"
                rescol['field'] = "publishedDate"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "Application"
                rescol['field'] = "application"
                results['columns'].append(rescol)

                with open("/var/DB/feeds/plugins/plugins.json", "r") as f:
                    jsonData = json.load(f)

                jsonData = jsonData['data']

                if application:
                    jsonData = list(filter(lambda x: (x['application'] == application), jsonData))
                if severity:
                    jsonData = list(filter(lambda x: (x['baseseverity3'] == severity), jsonData))
                    jsonData = list(filter(lambda x: (x['baseseverity2'] == severity), jsonData))
                if attackvector:
                    jsonData = list(filter(lambda x: (x['attackvector3'] == attackvector), jsonData))
                    jsonData = list(filter(lambda x: (x['attackvector2'] == attackvector), jsonData))
                if cwe_text:
                    jsonData = list(filter(lambda x: (x['cwe_text'] == cwe_text), jsonData))
                if basescore:
                    jsonData = list(filter(lambda x: (x['basescore3'] == basescore), jsonData))
                    jsonData = list(filter(lambda x: (x['basescore2'] == basescore), jsonData))

                results['total'] = len(jsonData)
                results['rowlimit'] = rowlimit
                results['results'] = jsonData[int(pageoffset):int(rowlimit)]

            elif type == "platform":
                results['results'] = []
                results['columns'] = []

                rescol = {}
                rescol['title'] = "Vulnerability"
                rescol['field'] = "vulnerability"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "Platform"
                rescol['field'] = "linux"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "Publish Date"
                rescol['field'] = "publishedDate"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "Severity"
                rescol['field'] = "baseseverity"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "CWEID"
                rescol['field'] = "cwe_text"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "baseScore"
                rescol['field'] = "basescore"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "AttackVector"
                rescol['field'] = "attackvector"
                results['columns'].append(rescol)

                with open("/var/DB/feeds/platforms/platform.json", "r") as f:
                    jsonData = json.load(f)

                jsonData = jsonData['data']

                if application:
                    jsonData = list(filter(lambda x: (application in x['linux']), jsonData))
                if severity:
                    jsonData = list(filter(lambda x: (x['baseseverity3'] == severity), jsonData))
                    jsonData = list(filter(lambda x: (x['baseseverity2'] == severity), jsonData))
                if attackvector:
                    jsonData = list(filter(lambda x: (x['attackvector3'] == attackvector), jsonData))
                    jsonData = list(filter(lambda x: (x['attackvector2'] == attackvector), jsonData))
                if cwe_text:
                    jsonData = list(filter(lambda x: (x['cwe_text'] == cwe_text), jsonData))
                if basescore:
                    jsonData = list(filter(lambda x: (x['basescore3'] == basescore), jsonData))
                    jsonData = list(filter(lambda x: (x['basescore2'] == basescore), jsonData))

                results ['total'] = len(jsonData)
                results['rowlimit'] = rowlimit
                results['results'] = jsonData[int(pageoffset):int(rowlimit)]

            elif type == "language":
                results['results'] = []
                results['columns'] = []

                rescol = {}
                rescol['title'] = "Vulnerability"
                rescol['field'] = "vulnerability"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "CWEID"
                rescol['field'] = "cwe_text"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "Severity"
                rescol['field'] = "baseseverity"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "baseScore"
                rescol['field'] = "basescore"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "Attack Vector"
                rescol['field'] = "attackvector"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "PublishDate"
                rescol['field'] = "publishedDate"
                results['columns'].append(rescol)

                rescol = {}
                rescol['title'] = "Application"
                rescol['field'] = "application"
                results['columns'].append(rescol)

                with open("/var/DB/feeds/language/languages.json", "r") as f:
                    jsonData = json.load(f)

                jsonData = jsonData['data']

                if application:
                    jsonData = list(filter(lambda x: (x['application'] == application), jsonData))
                if severity:
                    jsonData = list(filter(lambda x: (x['baseseverity3'] == severity), jsonData))
                    jsonData = list(filter(lambda x: (x['baseseverity2'] == severity), jsonData))
                if attackvector:
                    jsonData = list(filter(lambda x: (x['attackvector3'] == attackvector), jsonData))
                    jsonData = list(filter(lambda x: (x['attackvector2'] == attackvector), jsonData))
                if cwe_text:
                    jsonData = list(filter(lambda x: (x['cwe_text'] == cwe_text), jsonData))
                if basescore:
                    jsonData = list(filter(lambda x: (x['basescore3'] == basescore), jsonData))
                    jsonData = list(filter(lambda x: (x['basescore2'] == basescore), jsonData))

                results['total'] = len(jsonData)
                results['rowlimit'] = rowlimit	
                results['results'] = jsonData[int(pageoffset):int(rowlimit)]
            else:
                results['columns'] = []

                resCol = {}
                resCol['title'] = "Vulnerability"
                resCol['field'] = "vulnerability"
                results['columns'].append(resCol)

                rescol = {}
                rescol['title'] = "baseScore(v2/v3)"
                rescol['field'] = "baseScore"
                results['columns'].append(rescol)

                resCol = {}
                resCol['title'] = "AccessVector(v2/v3)"
                resCol['field'] = "accessvector"
                results['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Severity(v2/v3)"
                resCol['field'] = "severity"
                results['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "CWE"
                resCol['field'] = "cwe"
                results['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "LastModified"
                resCol['field'] = "lastModifiedDate"
                results['columns'].append(resCol)

                f = open("/var/DB/feeds/nvd/vuln_feed.json", "r")
                jsonCVEsData = json.load(f)
                jsonData = jsonCVEsData

                results['total'] = len(jsonData)
                results['rowlimit'] = rowlimit

                if severity:
                    jsonData = list(filter(lambda x: (x['baseSeverityv3'] == severity), jsonData))
                    jsonData = list(filter(lambda x: (x['baseSeverityv2'] == severity), jsonData))
                if attackvector:
                    jsonData = list(filter(lambda x: (x['attackVectorv3'] == attackvector), jsonData))
                    jsonData = list(filter(lambda x: (x['attackVectorv2'] == attackvector), jsonData))
                if cwe_text:
                    jsonData = list(filter(lambda x: (x['cwe_text'] == cwe_text), jsonData))
                if basescore:
                    jsonData = list(filter(lambda x: (x['baseScorev3'] == basescore), jsonData))
                    jsonData = list(filter(lambda x: (x['baseScorev2'] == basescore), jsonData))

                results['results'] = jsonData[int(pageoffset):int(rowlimit)]

            return jsonify(results)
        else:
            res = {}
            res['error'] = 2
            return jsonify(res)
    else:
        res = {}
        res['error'] = 3
        return jsonify(res)


# API to get vulnerabilities details for specified filters.
@app.route('/api/v1/vuln/list', methods=["GET"])
#@jwt_required
def getv1data():
    if 'email_id' in request.args and 'code' in request.args:
        email_id = request.args.get('type')
        code = request.args.get('code')
    else:
        res = {}
        res['error'] = 1
        return jsonify(res)

    query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
    print(query)
    g.cursor.execute(query)
    status_data = g.cursor.fetchall()
    
    if len(status_data) > 0:
        if status_data[0][0] == "active":
            if request.args.get('type'):
                type = request.args.get('type')
            else:
                type = ''
            if request.args.get('product'):
                application = request.args.get('product')
            else:
                application = ''
            if request.args.get('productname'):
                product = request.args.get('productname')
            else:
                product = ''
            if request.args.get('vendorname'):
                vendor = request.args.get('vendorname')
            else:
                vendor = ''
            if request.args.get('severity'):
                severity = request.args.get('severity')
                severity = severity.upper()
            else:
                severity = ''
            if request.args.get('attackVector'):
                attackvector = request.args.get('attackVector')
                attackvector = attackvector.upper()
            else:
                attackvector = ''
            if request.args.get('cwe_text'):
                cwe_text = request.args.get('cwe_text')
                cwe_text = cwe_text.upper()
            else:
                cwe_text = ''
            if request.args.get('basescore'):
                basescore = request.args.get('basescore')
            else:
                basescore = ''

            if request.args.get('offset'):
                pageoffset = request.args.get('offset')
                if request.args.get('limit'):
                    rowlimit = request.args.get('limit')
                else:
                    rowlimit = 50
            else:
                pageoffset = 0
                rowlimit = 50
                
            rowlimit = int(pageoffset) + int(rowlimit)

            results = {}
            results['results'] = []

            if type == "plugin":
                with open("/var/DB/feeds/plugins/plugins.json", "r") as f:
                    jsonData = json.load(f)

                jsonData = jsonData['data']

                if application:
                    jsonData = list(filter(lambda x: (x['application'] == application), jsonData))
                if severity:
                    jsonData = list(filter(lambda x: (x['baseseverity3'] == severity), jsonData))
                    jsonData = list(filter(lambda x: (x['baseseverity2'] == severity), jsonData))
                if attackvector:
                    jsonData = list(filter(lambda x: (x['attackvector3'] == attackvector), jsonData))
                    jsonData = list(filter(lambda x: (x['attackvector2'] == attackvector), jsonData))
                if cwe_text:
                    jsonData = list(filter(lambda x: (x['cwe_text'] == cwe_text), jsonData))
                if basescore:
                    jsonData = list(filter(lambda x: (x['basescore3'] == basescore), jsonData))
                    jsonData = list(filter(lambda x: (x['basescore2'] == basescore), jsonData))

                results['total'] = len(jsonData)
                results['rowlimit'] = rowlimit
                results['results'] = jsonData[int(pageoffset):int(rowlimit)]
            elif type == "platform":
                with open("/var/DB/feeds/platforms/platform.json", "r") as f:
                    jsonData = json.load(f)

                jsonData = jsonData['data']

                if application:
                    jsonData = list(filter(lambda x: (application in x['linux']), jsonData))
                if severity:
                    jsonData = list(filter(lambda x: (x['baseseverity3'] == severity), jsonData))
                    jsonData = list(filter(lambda x: (x['baseseverity2'] == severity), jsonData))
                if attackvector:
                    jsonData = list(filter(lambda x: (x['attackvector3'] == attackvector), jsonData))
                    jsonData = list(filter(lambda x: (x['attackvector2'] == attackvector), jsonData))
                if cwe_text:
                    jsonData = list(filter(lambda x: (x['cwe_text'] == cwe_text), jsonData))
                if basescore:
                    jsonData = list(filter(lambda x: (x['basescore3'] == basescore), jsonData))
                    jsonData = list(filter(lambda x: (x['basescore2'] == basescore), jsonData))

                results['total'] = len(jsonData)
                results['rowlimit'] = rowlimit
                results['results'] = jsonData[int(pageoffset):int(rowlimit)]

            elif type == "language":
                with open("/var/DB/feeds/language/languages.json", "r") as f:
                    jsonData = json.load(f)

                jsonData = jsonData['data']

                if application:
                    jsonData = list(filter(lambda x: (x['application'] == application), jsonData))
                if severity:
                    jsonData = list(filter(lambda x: (x['baseseverity3'] == severity), jsonData))
                    jsonData = list(filter(lambda x: (x['baseseverity2'] == severity), jsonData))
                if attackvector:
                    jsonData = list(filter(lambda x: (x['attackvector3'] == attackvector), jsonData))
                    jsonData = list(filter(lambda x: (x['attackvector2'] == attackvector), jsonData))
                if cwe_text:
                    jsonData = list(filter(lambda x: (x['cwe_text'] == cwe_text), jsonData))
                if basescore:
                    jsonData = list(filter(lambda x: (x['basescore3'] == basescore), jsonData))
                    jsonData = list(filter(lambda x: (x['basescore2'] == basescore), jsonData))

                results['total'] = len(jsonData)
                results['rowlimit'] = rowlimit	
                results['results'] = jsonData[int(pageoffset):int(rowlimit)]
            else:
                f = open("/var/DB/feeds/nvd/vuln_feed.json", "r")
                jsonCVEsData = json.load(f)
                jsonData = jsonCVEsData

                results['total'] = len(jsonData)
                results['rowlimit'] = rowlimit

                if severity:
                    jsonData = list(filter(lambda x: (x['baseSeverityv3'] == severity), jsonData))
                    jsonData = list(filter(lambda x: (x['baseSeverityv2'] == severity), jsonData))
                if attackvector:
                    jsonData = list(filter(lambda x: (x['attackVectorv3'] == attackvector), jsonData))
                    jsonData = list(filter(lambda x: (x['attackVectorv2'] == attackvector), jsonData))
                if cwe_text:
                    jsonData = list(filter(lambda x: (x['cwe_text'] == cwe_text), jsonData))
                if basescore:
                    jsonData = list(filter(lambda x: (x['baseScorev3'] == basescore), jsonData))
                    jsonData = list(filter(lambda x: (x['baseScorev2'] == basescore), jsonData))

                results['results'] = jsonData[int(pageoffset):int(rowlimit)]

            return jsonify(results)
        else:
            res = {}
            res['error'] = 2
            return jsonify(res)
    else:
        res = {}
        res['error'] = 3
        return jsonify(res)


# API to get Browse tab data in vulnerability DB page.
@app.route('/api/dash/browse', methods = ['GET'])
#@jwt_required
def getdashBrowse():
    if request.method == 'GET':
        with open('/var/DB/feeds/browse/allcves.json') as f:
            advData = json.load(f)

        vulnerabilities = advData['vulnerabilities'][:10]
        products = advData['product'][:10]
        vendors = advData['vendor'][:10]

        results = {}
        results['data'] = []

        res = {}
        res['header'] = "By Vendor"
        res['title'] = "Top 10 vendors by vulnerability count"
        res['data'] = vendors
        res['column'] = [] 
        res['column'].append('totalvuln')
        res['column'].append('vendor')
        results['data'] .append(res)


        res = {}
        res['header'] = "By Product"
        res['title'] = "Top 10 products by vulnerability count"
        res['data'] = products
        res['column'] = [] 
        res['column'].append('totalvuln')
        res['column'].append('product')
        results['data'] .append(res)

        res = {}
        res['header'] = "By Vulnerability Type"
        res['title'] = "Top 10 vulnerability type count"
        res['data'] = vulnerabilities
        res['column'] = [] 
        res['column'].append('totalvuln')
        res['column'].append('name')
        results['data'] .append(res)

        return jsonify(results)
   
# APi to get home data in vulnerability DB page.
@app.route('/api/scan/home', methods = ['GET'])
def getHome():
    if request.method == 'GET':
        if request.args.get('type'):
            type = request.args.get('type')
        else:
            type = ''

        results = {}

        results['columns'] = []

        resCol = {}
        resCol['title'] = "Vulnerability"
        resCol['field'] = "vulnerability"
        results['columns'].append(resCol)

        rescol = {}
        rescol['title'] = "baseScore(v2/v3)"
        rescol['field'] = "baseScore"
        results['columns'].append(rescol)

        resCol = {}
        resCol['title'] = "AccessVector(v2/v3)"
        resCol['field'] = "accessvector"
        results['columns'].append(resCol)

        resCol = {}
        resCol['title'] = "Severity(v2/v3)"
        resCol['field'] = "severity"
        results['columns'].append(resCol)

        resCol = {}
        resCol['title'] = "CWE"
        resCol['field'] = "cwe"
        results['columns'].append(resCol)

        resCol = {}
        resCol['title'] = "LastModified"
        resCol['field'] = "lastModifiedDate"
        results['columns'].append(resCol)

        results['rowlimit'] = 50

        f = open("/var/DB/feeds/nvd/vuln_feed.json", "r")
        jsonCVEsData = json.load(f)
        jsonData = jsonCVEsData

        if request.args.get('year'):
            year = request.args.get('year')
            if year.lower() == "all":
                jsonData = jsonData
            else:
                jsonData = list(filter(lambda x: (year == x['year']), jsonData))

        if type == "product":
            if request.args.get('product'):
                product = request.args.get('product')
                jsonData = list(filter(lambda x: (product in x['products']), jsonData))

            if request.args.get('producttype'):
                producttype = request.args.get('producttype')

                if producttype == "os":
                    producttype = "o"
                if producttype == "application":
                    producttype = "a"
                if producttype == "hardware":
                    producttype = "h"

                jsonData = list(filter(lambda x: (producttype in x['part']), jsonData))

        if type == "vulnerabilities":
            if request.args.get('cweid'):
                cwe = "CWE-%s" % request.args.get('cweid')
                jsonData = list(filter(lambda x: (cwe in x['cwe'].split(",")), jsonData))

        if type == "vendor":
            if request.args.get('vendor'):
                vendor = request.args.get('vendor')
                jsonData = list(filter(lambda x: (vendor in x['vendors']), jsonData))

        if type == "language":
            if request.args.get('language'):
                language = request.args.get('language')
                jsonData = list(filter(lambda x: ('language' in x), jsonData))
                jsonData = list(filter(lambda x: (language in x['language']), jsonData))

        if type == "platform":
            if request.args.get('platform'):
                platform = request.args.get('platform')
                jsonData = list(filter(lambda x: ('family' in x), jsonData))
                jsonData = list(filter(lambda x: (platform in x['family']), jsonData))

        if type == "plugin":
            if request.args.get('plugin'):
                plugin = request.args.get('plugin')
                jsonData = list(filter(lambda x: ('plugin' in x), jsonData))
                jsonData = list(filter(lambda x: (plugin in x['plugin']), jsonData))

        if request.args.get('local'):
            jsonData = list(filter(lambda x: ('LOCAL' in x['accessvector']), jsonData))

        if request.args.get('remote'):
            jsonData = list(filter(lambda x: ('NETWORK' in x['accessvector']), jsonData))

        if request.args.get('severity'):
            severity = request.args.get('severity')
            jsonData = list(filter(lambda x: (severity.upper() in x['severity'].upper()), jsonData))

        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50

        rowlimit = int(pageoffset) + int(rowlimit)
        results['rowlimit'] = rowlimit
        results['results'] = jsonData[int(pageoffset):int(rowlimit)]
        results['total'] = len(jsonData)

        return jsonify(results)


# APi to get specific product/vendor/vulnerability wise filter browse data in vulnerability page.
@app.route('/api/scan/browse', methods = ['GET'])
#@jwt_required
def getBrowse():
    if request.method == 'GET':
        if request.args.get('type'):
            type = request.args.get('type')
        else:
            type = ''

        resRet = {}
        resRet['columns'] = []

        if type == "vulnerabilities":
            res = {}
            res['field'] = 'cwe_text'
            res['title'] = 'CWE'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'name'
            res['title'] = 'Vulnerability'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'severity'
            res['title'] = 'Severity'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'totalvuln'
            res['title'] = 'Total'
            resRet['columns'].append(res)
        
        if type == "product" or type == "":
            res = {}
            res['field'] = 'product'
            res['title'] = 'Product'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'vendor'
            res['title'] = 'Vendor'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'producttype'
            res['title'] = 'Producttype'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'severity'
            res['title'] = 'Severity'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'totalvuln'
            res['title'] = 'Total'
            resRet['columns'].append(res)

        if type == "vendor":
            res = {}
            res['field'] = 'vendor'
            res['title'] = 'Vendor'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'totalpackages'
            res['title'] = 'Total Packages'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'severity'
            res['title'] = 'Severity'
            resRet['columns'].append(res)

            res = {}
            res['field'] = 'totalvuln'
            res['title'] = 'Total'
            resRet['columns'].append(res)

        if request.args.get('year'):
            year = request.args.get('year')
        else:
            year = ''
            
        if type == "product":
            if request.args.get('producttype'):
                producttype = request.args.get('producttype')
                if producttype == "os":
                    producttype = "o"
                if producttype == "application":
                    producttype = "a"
                if producttype == "hardware":
                    producttype = "h"
            else:
                producttype = ''
            
            if request.args.get('product'):
                product = request.args.get('product')
            else:
                product = ''

        if request.args.get('offset'):
            pageoffset = request.args.get('offset')
            if request.args.get('limit'):
                rowlimit = request.args.get('limit')
            else:
                rowlimit = 50
        else:
            pageoffset = 0
            rowlimit = 50
        
        rowlimit = int(pageoffset) + int(rowlimit)

        resRet['rowlimit'] = rowlimit

        if year:
            with open('/var/DB/feeds/browse/%s.json' % year) as f:
                advData = json.load(f)
        else:	
            with open('/var/DB/feeds/browse/allcves.json') as f:
                advData = json.load(f)

        if type == "vulnerabilities":
            if request.args.get('cweid'):
                cweid = "CWE-%s" % request.args.get('cweid')
            else:
                cweid = ''
            
            if cweid:
                vulnerabilities = list(filter(lambda x: (x['cwe_text'] == cweid), advData['vulnerabilities']))
                resRet['results'] = vulnerabilities[int(pageoffset):int(rowlimit)]
                return jsonify(resRet)
            else:
                vulnerabilities = advData['vulnerabilities']
                resRet['results'] = vulnerabilities[int(pageoffset):int(rowlimit)]
                return jsonify(resRet)

        if type == "product":
            if producttype:
                products = list(filter(lambda x: (x['producttype'] == producttype), advData['product']))
            else:
                products = advData['product']

            if product:
                products = list(filter(lambda x: (x['product'] == product), products))

            resRet['results'] = products[int(pageoffset):int(rowlimit)]
            return jsonify(resRet)

        if type == "vendor":
            if request.args.get('vendor'):
                vendor = request.args.get('vendor')
            else:
                vendor = ''
            
            if vendor:
                vendors = list(filter(lambda x: (x['vendor'] == vendor), advData['vendor']))
                resRet['results'] = vendors[int(pageoffset):int(rowlimit)]
                return jsonify(resRet)
            else:
                vendors = advData['vendor']
                resRet['results'] = vendors[int(pageoffset):int(rowlimit)]
                return jsonify(resRet)    


# APi to get specific product/vendor/vulnerability wise filter browse data in vulnerability page.
@app.route('/api/v1/scan/browse', methods = ['GET'])
#@jwt_required
def getv1Browse():
    if request.method == 'GET':
        if 'email_id' in request.args and 'code' in request.args:
            email_id = request.args.get('type')
            code = request.args.get('code')
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if len(status_data) > 0:
            if status_data[0][0] == "active":        
                if request.args.get('type'):
                    type = request.args.get('type')
                else:
                    type = ''

                resRet = {}
                
                if request.args.get('year'):
                    year = request.args.get('year')
                else:
                    year = ''
                
                producttype = ''

                if type == "product":
                    if request.args.get('producttype'):
                        producttype = request.args.get('producttype')
                        if producttype == "os":
                            producttype = "o"
                        if producttype == "application":
                            producttype = "a"
                        if producttype == "hardware":
                            producttype = "h"
                    else:
                        producttype = ''
                    
                    if request.args.get('product'):
                        product = request.args.get('product')
                    else:
                        product = ''

                if request.args.get('offset'):
                    pageoffset = request.args.get('offset')
                    if request.args.get('limit'):
                        rowlimit = request.args.get('limit')
                    else:
                        rowlimit = 50
                else:
                    pageoffset = 0
                    rowlimit = 50
                
                rowlimit = int(pageoffset) + int(rowlimit)

                resRet['rowlimit'] = rowlimit

                if year:
                    with open('/var/DB/feeds/browse/%s.json' % year) as f:
                        advData = json.load(f)
                else:	
                    with open('/var/DB/feeds/browse/allcves.json') as f:
                        advData = json.load(f)

                if type == "vulnerabilities":
                    if request.args.get('cweid'):
                        cweid = "CWE-%s" % request.args.get('cweid')
                    else:
                        cweid = ''
                    
                    if cweid:
                        vulnerabilities = list(filter(lambda x: (x['cwe_text'] == cweid), advData['vulnerabilities']))
                        resRet['results'] = vulnerabilities[int(pageoffset):int(rowlimit)]
                        return jsonify(resRet)
                    else:
                        vulnerabilities = advData['vulnerabilities']
                        resRet['results'] = vulnerabilities[int(pageoffset):int(rowlimit)]
                        return jsonify(resRet)

                elif type == "product":
                    if producttype:
                        products = list(filter(lambda x: (x['producttype'] == producttype), advData['product']))
                    else:
                        products = advData['product']

                    if product:
                        products = list(filter(lambda x: (x['product'] == product), products))

                    resRet['results'] = products[int(pageoffset):int(rowlimit)]
                    return jsonify(resRet)

                elif type == "vendor":
                    if request.args.get('vendor'):
                        vendor = request.args.get('vendor')
                    else:
                        vendor = ''
                    
                    if vendor:
                        vendors = list(filter(lambda x: (x['vendor'] == vendor), advData['vendor']))
                        resRet['results'] = vendors[int(pageoffset):int(rowlimit)]
                        return jsonify(resRet)
                    else:
                        vendors = advData['vendor']
                        resRet['results'] = vendors[int(pageoffset):int(rowlimit)]
                        return jsonify(resRet)
                
                else:
                    resRet['results'] = advData['product'][int(pageoffset):int(rowlimit)]
                    return jsonify(resRet)
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)

# API to get platform feed data. (this API call by niah scanner and celery machine)
@app.route('/api/scan/platform/<platform>/<osname>', methods = ['POST', 'GET'])
#@jwt_required
def getPlatform(platform, osname):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['type']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if len(status_data) > 0:
            if status_data[0][0] == "active":
                with open("/var/DB/feeds/platform/%s_%s.json" % (platform, osname), "r") as f:
                    jsonData = json.load(f)

                return jsonify(jsonData)
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)


# API to get specified language (python/php/java/javascript) products feeds. (this API call by niah scanner and celery machine)
@app.route('/api/scan/language/<application>', methods = ['POST', 'GET'])
#@jwt_required
def getLanguage(application):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['type']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if len(status_data) > 0:
            if status_data[0][0] == "active":                
                productLists = req_data['data']

                res = {}
                res['results'] = []

                productLists = productLists.split(",")

                with open("/var/DB/feeds/language/%s.json" % application, "r") as f:
                    jsonData = json.load(f)
                    
                jsonDataArray = jsonData['data']
                for p in productLists:
                    product = p.strip()
                    jsonData = list(filter(lambda x: (x['product'] == product), jsonDataArray))

                    if len(jsonData) > 0:
                        for d in jsonData:
                            resRet = {}
                            resRet['cve_id'] = d['cve_id']
                            resRet['vuln_name'] = d['vuln_name']
                            resRet['product'] = d['product']
                            resRet['vendor'] = d['vendor']

                            if application == "javascript":
                                resRet['available_versions'] = web_helper_obg.getnpm_javascript_mvers(d['product'], d['version'])
                            else:
                                resRet['available_versions'] = ''

                            resRet['versions'] = d['version']

                            resRet['severityV2'] = d['severityV2']
                            resRet['severityV3'] = d['severityV3']
                            if d['severityV3']:
                                resRet['severity'] = d['severityV3']
                            else:
                                resRet['severity'] = d['severityV2']
                            resRet['vectorstringV2'] = d['vectorStringV2']
                            resRet['vectorstringV3'] = d['vectorStringV3']
                            if d['vectorStringV3']:
                                resRet['vectorstring'] = d['vectorStringV3']
                            else:
                                resRet['vectorstring'] = d['vectorStringV2']
                            resRet['basescoreV2'] = d['baseScoreV2']
                            resRet['basescoreV3'] = d['baseScoreV3']
                            if d['baseScoreV3']:
                                resRet['basescore'] = d['baseScoreV3']
                            else:
                                resRet['basescore'] = d['baseScoreV2']
                            resRet['pub_date'] = d['publishedDate']
                            resRet['reference'] = d['reference']
                            resRet['description'] = d['description']
                            resRet['patch'] = d['patch']
                            resRet['cwe_text'] = d['cwe']
                            resRet['cwe_id'] = d['cwe_text']
                            if 'groupid' in d:
                                resRet['groupid'] = d['groupid']
                            if 'artifactid' in d:
                                resRet['artifactid'] = d['artifactid']
                            if 'packagename' in d:
                                resRet['packagename'] = d['packagename']
                            resRet['exploits'] = d['exploits']

                            resRet['accessvectorV2'] = d['accessvectorV2']
                            resRet['accessvectorV3'] = d['accessvectorV3']
                            resRet['accessvector'] = d['accessvector']
                            res['results'].append(resRet)
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)
        
        return res

# API to get specified language (python/php/java/javascript) products feeds. (this API call by niah scanner and celery machine) (This API also match vendor)
@app.route('/api/scan/vendor/language/<application>', methods = ['POST', 'GET'])
#@jwt_required
def getVendorLanguage(application):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['type']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if len(status_data) > 0:
            if status_data[0][0] == "active":        
                productLists = req_data['data']

                res = {}
                res['results'] = {}

                productLists = productLists.split(",")

                with open("/var/DB/feeds/language/%s.json" % application, "r") as f:
                    jsonData = json.load(f)
                    
                jsonDataArray = jsonData['data']

                for p in productLists:
                    product = p.split('/')[1]
                    vendor = p.split('/')[0]

                    jsonData = list(filter(lambda x: (x['product'] == product), jsonDataArray))

                    if vendor:
                        jsonData = list(filter(lambda x: (x['vendor'] == vendor), jsonData))

                    if len(jsonData) > 0:
                        if product not in res['results']:
                            res['results'][product] = []

                        for d in jsonData:
                            resRet = {}
                            resRet['cve_id'] = d['cve_id']
                            resRet['product'] = product
                            resRet['vendor'] = vendor
                            resRet['versions'] = d['version']

                            resRet['severityV2'] = d['severityV2']
                            resRet['severityV3'] = d['severityV3']
                            resRet['severity'] = d['severity']

                            resRet['vectorstringV2'] = d['vectorStringV2']
                            resRet['vectorstringV3'] = d['vectorStringV3']
                            resRet['vectorstring'] = d['vectorString']
                            resRet['basescoreV2'] = d['baseScoreV2']
                            resRet['basescoreV3'] = d['baseScoreV3']
                            resRet['basescore'] = d['baseScore']
                            resRet['pub_date'] = d['publishedDate']
                            resRet['reference'] = d['reference']
                            resRet['description'] = d['description']
                            resRet['patch'] = d['patch']
                            resRet['cwe_text'] = d['cwe']
                            resRet['cwe_id'] = d['cwe_text']
                            if 'groupid' in d:
                                resRet['groupid'] = d['groupid']
                            if 'artifactid' in d:
                                resRet['artifactid'] = d['artifactid']
                            resRet['exploits'] = d['exploits']

                            resRet['accessvectorV2'] = d['accessvectorV2']
                            resRet['accessvectorV3'] = d['accessvectorV3']
                            resRet['accessvector'] = d['accessvector']
                            res['results'][product].append(resRet)
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)

        return res

# API to fetch Plugins vulnerabilities details. (This API is call by niah scanner and celery machine)
@app.route('/api/scanDetailsPlugin/<application>', methods = ['POST', 'GET'])
@jwt_required
def getProductVersionPlugin(application):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if len(status_data) > 0:
            if status_data[0][0] == "active":
                productLists = req_data['data']

                res = {}
                res['results'] = {}
                productLists = productLists.split(",")

                for product in productLists:
                    jsonData = list(filter(lambda x: (x['product'] == product), jsonData))
                    if len(jsonData) > 0:
                        if product not in res['results']:
                            res['results'][product] = []

                        for d in jsonData:
                            resRet = {}
                            resRet['product'] = d['product']
                            resRet['vulnName'] = d['vulnerability']
                            resRet['cve_id' ] = d['cve_id']
                            resRet['publish_date'] = d['publishedDate']
                            resRet['versions'] = d['versions']
                            resRet['reference'] = d['reference']
                            resRet['description'] = d['description']
                            resRet['cwe_text'] = d['cwe_text']
                            resRet['exploits'] = d['exploits']
                            resRet['patch'] = d['patch']

                            if d['baseseverity2']:
                                resRet['severity'] = d['baseseverity2']
                            elif d['baseseverity3']:
                                resRet['severity'] = d['baseseverity2']
                            else:
                                resRet['severity'] = 'UNKNOWN'

                            if d['vectorstring2']:
                                resRet['vectorString'] = d['vectorstring2']
                            elif d['vectorstring3']:
                                resRet['vectorString'] = d['vectorstring3']
                            else:
                                resRet['vectorString'] = 'UNKNOWN'
                            
                            if 	d['basescore2']:	
                                resRet['baseScore'] = d['basescore2']
                            elif d['basescore3']:
                                resRet['baseScore'] = d['basescore3']
                            else:
                                resRet['baseScore'] = 'UNKNOWN'

                            if d['attackvector2']:
                                resRet['attackVector'] = d['attackvector2']
                            elif d['attackvector3']:
                                resRet['attackVector'] = d['attackvector3']
                            else:
                                resRet['attackVector'] = 'UNKNOWN'
                            res['results'][product].append(resRet)

                return res
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)


# API to fetch applications vulnerabilities details. (This API is call by niah scanner and celery machine)
@app.route('/api/vulnapp', methods = ['POST', 'GET'])
@jwt_required
def getappdb():
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
        
        if len(status_data) > 0:
            if status_data[0][0] == "active":
                productLists = req_data['data']

                with open("/var/DB/feeds/application/application.json", "r") as f:
                    jsonData = json.load(f)

                jsonDataArray = jsonData['data']

                results = {}
                for product in productLists.split(","):
                    product = product.lower()
                    if product not in results:
                        results[product] = []

                    jsonData = list(filter(lambda x: (x['product'] == product), jsonDataArray))
                
                    if len(jsonData) > 0:
                        for row in jsonData:
                            res = {}
                            product = row['product']
                            vendor = row['vendor']
                            cve_id = row['cve_id']
                            versions = row['versions']
                            patch = row['patch']
                            publishedDate = row['publishedDate']
                            attackvector = row['attackvector']
                            vectorstring = row['vectorstring']
                            basescore = row['basescore']
                            baseseverity = row['baseseverity']
                            cwe_text = row['cwe_text']
                            reference = row['reference']
                            vulnerability = row['vulnerability']
                            exploits = row['exploits']

                            res['product'] = product
                            res['vendor'] = vendor
                            res['cve_id'] = cve_id
                            res['versions'] = versions
                            res['patch'] = patch
                            res['publish_date'] = publishedDate
                            res['vuln_name'] = vulnerability
                            res['cwe_text'] = cwe_text
                            res['reference'] = reference
                            res['exploits'] = exploits

                            if row['baseseverity2']:
                                res['severity'] = row['baseseverity2']
                            elif row['baseseverity3']:
                                res['severity'] = row['baseseverity2']
                            else:
                                res['severity'] = 'UNKNOWN'

                            if row['vectorstring2']:
                                res['vectorString'] = row['vectorstring2']
                            elif row['vectorstring3']:
                                res['vectorString'] = row['vectorstring3']
                            else:
                                res['vectorString'] = 'UNKNOWN'
                            
                            if row['basescore2']:	
                                res['baseScore'] = row['basescore2']
                            elif row['basescore3']:
                                res['baseScore'] = row['basescore3']
                            else:
                                res['baseScore'] = 'UNKNOWN'

                            if row['attackvector2']:
                                res['attackVector'] = row['attackvector2']
                            elif row['attackvector3']:
                                res['attackVector'] = row['attackvector3']
                            else:
                                res['attackVector'] = 'UNKNOWN'

                            if res not in results[product]:
                                results[product].append(res)
                return results
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)

        else:
            res = {}
            res['error'] = 3
            return jsonify(res)


# API to get CVE details (This is authentication API which is available after login, and we handle alert detail of specified CVE)
@app.route('/api/auth/cve', methods=["GET"])
#@jwt_required
def cveSearchAuth():
    if 'email_id' in request.args and 'code' in request.args:
        email_id = request.args.get('email_id')
        code = request.args.get('code')
    else:
        res = {}
        res['error'] = 1
        return jsonify(res)
    
    query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
    print(query)
    g.cursor.execute(query)
    status_data = g.cursor.fetchall()
        
    if len(status_data) > 0:
        if status_data[0][0] == "active":
            user_id = email_id
            if request.args.get('cve'):
                cve_id = request.args.get('cve')
                
                if path.exists("/var/DB/CVEs/%s.json" % (cve_id)):
                    with open("/var/DB/CVEs/%s.json" % (cve_id)) as f:
                        results = json.load(f)
                else:
                    results = {}
                    results['Products'] = {}
                    results['microsoft_advisory'] = {}
                    results['platform_advisory'] = {}
                    results['library_advisory'] = {}
                    results['plugin_advisory'] = {}
                    results['application_advisory'] = {}
                
                retRes = results

                retRes['Products']['title'] = "NVD Products"
                retRes['Products']['columns'] = []

                resCol = {}
                resCol['title'] = "Product"
                resCol['field'] = "product"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Vendor"
                resCol['field'] = "vendor"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Versions"
                resCol['field'] = "version"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Patch"
                resCol['field'] = "patch"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Part"
                resCol['field'] = "type"
                retRes['Products']['columns'].append(resCol)

                
                if 'microsoft_advisory' in retRes:
                    retRes['microsoft_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "KB Artical"
                    resCol['field'] = "KBArtical"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Article Url"
                    resCol['field'] = "articleUrl"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Download Name"
                    resCol['field'] = "downloadName"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Download Url"
                    resCol['field'] = "DownloadUrl"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Supercedence KB"
                    resCol['field'] = "supercedence"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "Product"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Platform"
                    resCol['field'] = "Platform"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Publish Date"
                    resCol['field'] = "PublishDate"
                    retRes['microsoft_advisory']['columns'].appen(resCol)


                if 'platform_advisory' in retRes:
                    retRes['platform_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Package"
                    resCol['field'] = "product"
                    retRes['platform_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Platform"
                    resCol['field'] = "platform"
                    retRes['platform_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Advisory"
                    resCol['field'] = "advisoryid"
                    retRes['platform_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['platform_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Family"
                    resCol['field'] = "family"
                    retRes['platform_advisory']['columns'].append(resCol)

                if 'library_advisory' in retRes:
                    retRes['library_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "product"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Vendor"
                    resCol['field'] = "vendor"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Versions"
                    resCol['field'] = "version"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Language"
                    resCol['field'] = "language"
                    retRes['library_advisory']['columns'].append(resCol)
        

                if 'plugin_advisory' in retRes:
                    retRes['plugin_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "product"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Vendor"
                    resCol['field'] = "vendor"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Versions"
                    resCol['field'] = "versions"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Application"
                    resCol['field'] = "application"
                    retRes['plugin_advisory']['columns'].append(resCol)


                if 'application_advisory' in retRes:
                    retRes['application_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "product"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Vendor"
                    resCol['field'] = "vendor"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Versions"
                    resCol['field'] = "versions"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Application"
                    resCol['field'] = "application"
                    retRes['application_advisory']['columns'].append(resCol)
                

                
                cmd = "select * from alerttabs where user_id='%s' and alert_type='cve_id' and alert_name='%s'" % (user_id, cve_id)
                g.cursor.execute(cmd)
                fetchData = g.cursor.fetchall()

                if len(fetchData) == 0:
                    retRes['alert'] = False
                else:
                    retRes['alert'] = True
                
                return jsonify(retRes)
            else:
                retRes = {}
                retRes['error'] = True
                retRes['message'] = "Argument cve is require"
                return jsonify(retRes)
        else:
            res = {}
            res['error'] = 2
            return jsonify(res)
    else:
        res = {}
        res['error'] = 3
        return jsonify(res)

# API to get CVE details (This is authentication API which is available after login, and we handle alert detail of specified CVE)
@app.route('/api/v1/auth/cve', methods=["GET"])
#@jwt_required
def cvev1SearchAuth():
    if 'email_id' in request.args and 'code' in request.args:
        email_id = request.args.get('type')
        code = request.args.get('code')
    else:
        res = {}
        res['error'] = 1
        return jsonify(res)
    
    query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
    print(query)
    g.cursor.execute(query)
    status_data = g.cursor.fetchall()
        
    if len(status_data) > 0:
        if status_data[0][0] == "active":
            user_id = email_id
            if request.args.get('cve'):
                cve_id = request.args.get('cve')
                
                if path.exists("/var/DB/CVEs/%s.json" % (cve_id)):
                    with open("/var/DB/CVEs/%s.json" % (cve_id)) as f:
                        results = json.load(f)
                else:
                    results = {}
                
                retRes = results

                
                cmd = "select * from alerttabs where user_id='%s' and alert_type='cve_id' and alert_name='%s'" % (user_id, cve_id)
                g.cursor.execute(cmd)
                fetchData = g.cursor.fetchall()

                if len(fetchData) == 0:
                    retRes['alert'] = False
                else:
                    retRes['alert'] = True

                return jsonify(retRes)
            else:
                retRes = {}
                retRes['error'] = True
                retRes['message'] = "Argument cve is require"
                return jsonify(retRes)
        else:
            res = {}
            res['error'] = 2
            return jsonify(res)
    else:
        res = {}
        res['error'] = 3
        return jsonify(res)

# API to get specified plugin vulnerability details. (this API call by niah scanner or celery machine)
@app.route('/api/plugin/<application>', methods = ['POST', 'GET'])
@jwt_required
def getcmsdb(application):
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
            
        if len(status_data) > 0:
            if status_data[0][0] == "active":
                productLists = req_data['data']

                results = {}

                with open("/var/DB/feeds/plugins/%s_plugins.json" % application , "r") as f:
                    jsonData = json.load(f)

                jsonDataArray = jsonData['data']

                for product in productLists.split(","):
                    if product not in results:
                        results[product] = []

                    jsonData = list(filter(lambda x: (x['product'] == product), jsonDataArray))
            
                    for aDB in jsonData:
                        res = {}
                        res['product'] = aDB['product']
                        res['vendor'] = aDB['vendor']
                        res['cve_id'] = aDB['cve_id']
                        res['vuln_name'] = aDB['vulnerability']
                        res['versions'] = aDB['versions']
                        res['patch'] = aDB['patch']
                        res['baseScore'] = aDB['basescore']
                        res['vectorString'] = aDB['vectorstring']
                        res['severity'] = aDB['baseseverity']
                        res['publish_date'] = aDB['publishedDate']
                        res['accessvector'] = aDB['attackvector']
                        res['cwe_text'] = aDB['cwe_text']
                        res['reference'] = aDB['reference']

                        if res not in results[product]:
                            results[product].append(res)

                return results
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)
        

# This is product vulnerabilities details lists API. 
@app.route('/api/details/product', methods = ['POST', 'GET'])
def getDetails():
    if request.method == 'POST':
        req_data = request.get_json()

        if 'email_id' in req_data and 'code' in req_data:
            email_id = req_data['email_id']
            code = req_data['code']
        else:
            res = {}
            res['error'] = 1
            return jsonify(res)
    
        query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
        print(query)
        g.cursor.execute(query)
        status_data = g.cursor.fetchall()
            
        if len(status_data) > 0:
            if status_data[0][0] == "active":
                type = req_data['type']
                application = req_data['application']
                product = req_data['product']

                results = {}
                results['header'] = []

                res = {}
                res['product'] = product
                results['header'].append(res)

                res = {}
                res['type'] = application
                results['header'].append(res)

                if type == "dependencies" or type == "language":
                    with open("/var/DB/feeds/language/language.json", "r") as f:
                        jsonData = json.load(f)
                    jsonData = jsonData['data']
                    jsonData = list(filter(lambda x: (x['language'] == application), jsonData))
                    jsonData = list(filter(lambda x: (x['product'] == product), jsonData))

                if type == "platform" or type == "system":
                    with open("/var/DB/feeds/platform/%s.json" % application, "r") as f:
                        jsonData = json.load(f)
                    jsonData = jsonData['data']
                    jsonData = list(filter(lambda x: (x['product'] == product), jsonData))

                if type == "plugin":
                    with open("/var/DB/feeds/plugin/plugin.json", "r") as f:
                        jsonData = json.load(f)
                    jsonData = jsonData['data']
                    jsonData = list(filter(lambda x: (x['application'] == application), jsonData))
                    jsonData = list(filter(lambda x: (x['product'] == product), jsonData))

                if type == "application":
                    with open("/var/DB/feeds/application/application.json", "r") as f:
                        jsonData = json.load(f)
                    jsonData = jsonData['data']
                    jsonData = list(filter(lambda x: (x['product'].lower() == product.lower()), jsonData))

                res = {}
                res['total_vuln'] = len(jsonData)
                results['header'].append(res)
                    
                results['db'] = {}
                results['db']['columns'] = []
                results['db']['results'] = []

                res = {}
                res['title'] = "Vulnerability"
                res['field'] = "vulnerability"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "PublishDate"
                res['field'] = "publish_date"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "VectorString"
                res['field'] = "vectorstring"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "Severity"
                res['field'] = "severity"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "CWE"
                res['field'] = "cwe_text"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "Versions"
                res['field'] = "versions"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "Patch"
                res['field'] = "patch"
                results['db']['columns'].append(res)

                res = {}
                res['title'] = "attackVector"
                res['field'] = "attackVector"
                results['db']['columns'].append(res)

                tempCWE = {}
                tempSeverity = {}
            
                for aDB in jsonData:
                    res = {}
                    res['vulnerability'] = aDB['vuln_name']
                    res['publish_date'] = aDB['publishedDate']
                    res['vectorstring'] = aDB['vectorString']
                    res['vectorStringV3'] = aDB['vectorStringV3']
                    res['vectorStringV2'] = aDB['vectorStringV2']
                    res['accessvectorV3'] = aDB['accessvectorV3']
                    res['accessvectorV2'] = aDB['accessvectorV2']
                    res['severity'] = aDB['severity']
                    res['severityV3'] = aDB['severityV3']
                    res['severityV2'] = aDB['severityV2']
                    res['cwe_text'] = aDB['cwe_text']
                    res['versions'] = aDB['version']
                    res['patch'] = aDB['patch']
                    res['attackVector'] = aDB['accessvector']
                    results['db']['results'].append(res)
                    
                    cwe_text = aDB['cwe_text']
                    if cwe_text not in tempCWE:
                        tempCWE[cwe_text] = []
                    tempCWE[cwe_text].append(res)

                    if aDB['severityV3']:
                        severity = aDB['severityV3']
                    elif aDB['severityV2']:
                        severity = aDB['severityV2']
                    else:
                        severity = "UNKNOWN"

                    if severity not in tempSeverity:
                        tempSeverity[severity] = []
                    tempSeverity[severity].append(res)
                    
                results['chart'] = {}
                results['chart']['cwe'] = {}
                results['chart']['severity'] = {}

                for cweId in tempCWE:
                    results['chart']['cwe'][cweId] = len(tempCWE[cweId])
                    
                for severity in tempSeverity:
                    results['chart']['severity'][severity] = len(tempSeverity[severity])
        
                return jsonify(results)
            else:
                res = {}
                res['error'] = 2
                return jsonify(res)
        else:
            res = {}
            res['error'] = 3
            return jsonify(res)
            

# API to get CVE detail. (this is unauthentication API, which is call on main page.)
@app.route('/api/cve', methods=["GET"])
def cveSearch():
    if 'email_id' in request.args and 'code' in request.args:
        email_id = request.args.get('type')
        code = request.args.get('code')
    else:
        res = {}
        res['error'] = 1
        return jsonify(res)
    
    query = "select status from license_master_db where code='%s' and emailid='%s'" % (code, email_id)
    print(query)
    g.cursor.execute(query)
    status_data = g.cursor.fetchall()
        
    if len(status_data) > 0:
        if status_data[0][0] == "active":
            search_text = ''
            if request.args.get('cve'):
                cve_id = request.args.get('cve')

                year = cve_id.split("-")[1]

                if path.exists("/var/DB/CVEs/%s/%s.json" % (year, cve_id)):
                    with open("/var/DB/CVEs/%s/%s.json" % (year, cve_id)) as f:
                        results = json.load(f)
                else:
                    results = {}
                    retRes['Products'] = {}
                    retRes['microsoft_advisory'] = {}
                    retRes['platform_advisory'] = {}
                    retRes['library_advisory'] = {}
                    retRes['plugin_advisory'] = {}
                    retRes['application_advisory'] = {}


                retRes = results
                search_text = 'cve_id="%s"' % cve_id

                retRes['Products']['columns'] = []
                    
                resCol = {}
                resCol['title'] = "Product"
                resCol['field'] = "product"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Vendor"
                resCol['field'] = "vendor"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Versions"
                resCol['field'] = "version"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "patch"
                resCol['field'] = "patch"
                retRes['Products']['columns'].append(resCol)

                resCol = {}
                resCol['title'] = "Part"
                resCol['field'] = "type"
                retRes['Products']['columns'].append(resCol)

                if 'microsoft_advisory' in retRes:
                    retRes['microsoft_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "KB Artical"
                    resCol['field'] = "KBArtical"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Article Url"
                    resCol['field'] = "articleUrl"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Download Name"
                    resCol['field'] = "downloadName"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Download Url"
                    resCol['field'] = "DownloadUrl"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Supercedence KB"
                    resCol['field'] = "supercedence"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "Product"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Platform"
                    resCol['field'] = "Platform"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                    resCol = {}
                    resCol['title'] = "Publish Date"
                    resCol['field'] = "pub_date"
                    retRes['microsoft_advisory']['columns'].appen(resCol)

                if 'platform_advisory' in retRes:
                    retRes['platform_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Platform"
                    resCol['field'] = "Platform"
                    retRes['platform_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Reference"
                    resCol['field'] = "Reference"
                    retRes['platform_advisory']['columns'].append(resCol)

                if 'library_advisory' in retRes:
                    retRes['library_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "product"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Vendor"
                    resCol['field'] = "vendor"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Versions"
                    resCol['field'] = "version"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['library_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Language"
                    resCol['field'] = "language"
                    retRes['library_advisory']['columns'].append(resCol)

                if 'plugin_advisory' in retRes:
                    retRes['plugin_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "product"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Vendor"
                    resCol['field'] = "vendor"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Versions"
                    resCol['field'] = "versions"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['plugin_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Application"
                    resCol['field'] = "application"
                    retRes['plugin_advisory']['columns'].append(resCol)

                if 'application_advisory' in retRes:
                    retRes['application_advisory']['columns'] = []

                    resCol = {}
                    resCol['title'] = "Product"
                    resCol['field'] = "product"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Vendor"
                    resCol['field'] = "vendor"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Versions"
                    resCol['field'] = "versions"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Patch"
                    resCol['field'] = "patch"
                    retRes['application_advisory']['columns'].append(resCol)

                    resCol = {}
                    resCol['title'] = "Application"
                    resCol['field'] = "application"
                    retRes['application_advisory']['columns'].append(resCol)
                                    
                return jsonify(retRes)
            else:
                res = {}
                res['error'] = True
                res['message'] = "Argument cve is require"
                return jsonify(retRes)
        else:
            res = {}
            res['error'] = 2
            return jsonify(res)
    else:
        res = {}
        res['error'] = 3
        return jsonify(res)


# This API is to search CVEs details.
@app.route('/api/search/cve', methods=["GET"])
def cveWiseSearch():
    if request.method == 'GET':
        search_text = ''
        cve_id = ''

        if request.args.get('cve'):
            cve_id = request.args.get('cve')
            year = cve_id.split("-")[1]
        
            retRes = {}
            retRes['severity'] = {}
            retRes['snapshot'] = {}
            retRes['NIAH_Insights'] = []
            retRes['niah_meter'] = {}

            if path.exists("/var/DB/CVEs/%s.json" % (cve_id)):
                with open("/var/DB/CVEs/%s.json" % (cve_id), "r") as f:
                    results = json.load(f)
            else:
                results = {}
            
            jsonCVEsData = {}
            jsonCVEsData[year] = {}
            jsonCVEsData[year][cve_id] = results

            if 'description' in jsonCVEsData[year][cve_id]:
                retRes['snapshot']['Description'] = jsonCVEsData[year][cve_id]['description']
            else:
                retRes['snapshot']['Description'] = ''
            if 'CWE' in jsonCVEsData[year][cve_id]:
                retRes['snapshot']['CWEID'] = jsonCVEsData[year][cve_id]['CWE'] 
            if 'publishedDate' in jsonCVEsData[year][cve_id]:
                retRes['snapshot']['publishedDate'] = jsonCVEsData[year][cve_id]['publishedDate']
            else:
                retRes['snapshot']['publishedDate'] = ''

            if 'plugin_advisory' in jsonCVEsData[year][cve_id]:
                retRes['plugin_advisory'] = jsonCVEsData[year][cve_id]['plugin_advisory']

            if 'application_advisory' in jsonCVEsData[year][cve_id]:
                retRes['application_advisory'] = jsonCVEsData[year][cve_id]['application_advisory']

            if 'library_advisory' in jsonCVEsData[year][cve_id]:
                retRes['library_advisory'] = jsonCVEsData[year][cve_id]['library_advisory']

            if 'platform_advisory' in jsonCVEsData[year][cve_id]:
                retRes['platform_advisory'] = jsonCVEsData[year][cve_id]['platform_advisory']

            if 'microsoft_advisory' in jsonCVEsData[year][cve_id]:
                retRes['microsoft_advisory'] = jsonCVEsData[year][cve_id]['microsoft_advisory']

            if 'CVSS20' in jsonCVEsData[year][cve_id]:
                if 'baseScore' in jsonCVEsData[year][cve_id]['CVSS20']:
                    retRes['severity']['CVSS 2.0'] = jsonCVEsData[year][cve_id]['CVSS20']['baseScore']
                else:
                    retRes['severity']['CVSS 2.0'] = ''

            if 'CVSS30' in jsonCVEsData[year][cve_id]:
                if 'baseScore' in jsonCVEsData[year][cve_id]['CVSS30']:
                    retRes['severity']['CVSS 3.0'] = jsonCVEsData[year][cve_id]['CVSS30']['baseScore']
                else:
                    retRes['severity']['CVSS 3.0'] = ''

            if 'cwe_str' in jsonCVEsData[year][cve_id]:
                CWEStr = jsonCVEsData[year][cve_id]['cwe_str']
            else:
                CWEStr = ''

            
            dr_info_json = jsonCVEsData[year][cve_id]['Products']['data']

            dr_products_info = []
            dr_vendors_info = []
            dr_family_info = []
            dr_language_info = []
            dr_plugin_info = []
            dr_platform_info = []


            if len(dr_info_json) > 0:
                for dr_info in dr_info_json:
                    if 'products' in dr_info:
                        dr_products_info.append(dr_info['product'])
                    if 'vendors' in dr_info:
                        dr_vendors_info.append(dr_info['vendors'])
                    if 'family' in dr_info:
                        dr_family_info.append(dr_info['family'])
                    if 'language' in dr_info:
                        dr_language_info.append(dr_info['language'])
                    if 'plugin' in dr_info:
                        dr_plugin_info.append(dr_info['plugin'])
                    if 'platform' in dr_info:
                        dr_platform_info.append(dr_info['platform'])


            if CWEStr and CWEStr != "None":
                retRes['NIAH_Insights'].append("This is %s vulnerability" % CWEStr)
            if 'microsoft_advisory' in jsonCVEsData[year][cve_id]:
                retRes['NIAH_Insights'].append("There are %s Microsoft KBs published for this vulnerability" % len(jsonCVEsData[year][cve_id]['microsoft_advisory']['data']))
            if 'Exploits' in jsonCVEsData[year][cve_id]:
                if len(jsonCVEsData[year][cve_id]['Exploits']) > 0:
                    retRes['NIAH_Insights'].append("There are %s public exploits published for this vulnerability" % len(jsonCVEsData[year][cve_id]['Exploits']))
            
            if dr_platform_info:
                retRes['NIAH_Insights'].append("There are %s linux platform are found vulnerable. (%s)" % (len(dr_platform_info), ', '.join(dr_platform_info)))
            if dr_plugin_info:
                retRes['NIAH_Insights'].append("There are %s plugins are vulnerable. (%s)" % (len(dr_plugin_info), ', '.join(dr_plugin_info)))
            if dr_language_info:
                retRes['NIAH_Insights'].append("There are %s dependencies found vulnerable. (%s)" % (len(dr_language_info), ', '.join(dr_language_info)))
            if dr_family_info:
                retRes['NIAH_Insights'].append("There are %s family are vulnerable. (%s)" % (len(dr_family_info), ', '.join(dr_family_info)))
            if dr_vendors_info:
                retRes['NIAH_Insights'].append("There are %s vendor are vulnerable." % (len(dr_vendors_info)))
            if dr_products_info:
                retRes['NIAH_Insights'].append("There are %s products are vulnerable." % (len(dr_products_info)))


            retRes['niah_meter']['title'] = "Niah Worry Meter"
            retRes['niah_meter']['patch_now'] = "http://web.niahsecurity.io/"
            retRes['niah_meter']['speedometer'] = {}
            retRes['niah_meter']['speedometer']['min'] = "0"
            retRes['niah_meter']['speedometer']['max'] = "10"
            retRes['niah_meter']['speedometer']['default'] = "5"
            retRes['niah_meter']['segments'] = [0,4,6,10]
            retRes['niah_meter']['colors'] = ["#ff5355","#efd514","#3ccc5b"]
                                    
            return jsonify(retRes)
        else:
            res = {}
            res['error'] = True
            res['message'] = "Argument cve is require"
            return jsonify(retRes)

# Get Application.config file. This file is required for application scannning to get meta details of application like (application name, application version regex, application version file location).
@app.route('/api/getConfig')
def getAppConfig():
    with open("application.config") as f:
        configData = json.load(f)

    resRet = {}
    resRet['details'] = []
    return configData

@app.route('/api/update/counter', methods = ['POST', 'GET'])
def updateCounter(type):
    if request.method == 'POST':
        req_data = request.get_json()
        type = req_data['type']
        email_id = req_data['email_id']
        code = req_data['code']
        counter = req_data['counter']
        date = req_data['date']
        dst_ip = request.remote_addr

        query = "select status from license_master_db where emailid='%s' and code='%s'" % (email_id, code)
        print(query)
        g.cursor.execute(query)
        fdata = g.cursor.fetchall()

        if len(fdata) > 0:
            if fdata[0][0] == "active":
                query = "insert into counter_tab(type, email_id, counter, date, dst_ip) values('%s', '%s', '%s', '%s', ' %s')" % (type, email_id, counter, date, dst_ip)
                print(query)
                g.cursor.execute(query)
                g.conn.commit()

            res = {}
            res['error'] = False
            res['message'] = "counter updated"
            return jsonify(res)
        else:
            res = {}
            res['error'] = True
            res['message'] = "counter not updated, user deactivated"
            return jsonify(res)


@app.route('/api/check/license', methods = ['POST', 'GET'])
def checkLicense(type):
    if request.method == 'POST':
        req_data = request.get_json()
        email_id = req_data['email_id']
        code = req_data['code']

        query = "select status from license_master_db where emailid='%s' and code='%s'" % (email_id, code)
        print(query)
        g.cursor.execute(query)
        fdata = g.cursor.fetchall()

        if len(fdata) > 0:
            if fdata[0][0] == "active":
                res = {}
                res['status'] = 1
            else:
                res = {}
                res['status'] = 0
        else:
            res = {}
            res['status'] = 0

        return jsonify(res)

if __name__ == "__main__":
    app.run('0.0.0.0', port=8080, debug=True)
