# -*- coding: utf-8 -*-
"""
Created on Sun Apr  5 15:22:58 2015

@author: steve
"""
#REGEX_URL = '^((((https?|ftps?|gopher|telnet|nntp)://)|(mailto:|news:))(%[0-9A-Fa-f]{2}|[-()_.!~*';/?:@&=+$,A-Za-z0-9])+)([).!';/?:,][[:blank:]])?$]'
import re
import csv
# Match
REGEX_EMAIL = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$"
REGEX_IP4 = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
REGEX_IP6 = r'^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$'
REGEX_URL = r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
REGEX_ZIPCODE = r'^\d{5}(-\d{4})?$'
REGEX_RTN = r'^((0[0-9])|(1[0-2])|(2[1-9])|(3[0-2])|(6[1-9])|(7[0-2])|80)([0-9]{7})$'
# Parse
REGEX_URI = r'^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?'

def regex_validate(pattern, input_str):
    return bool(re.match(pattern, input_str))
    
def is_prefixed(input_str, prefix_str):
    return input_str[:len(prefix_str)].lower() == prefix_str



def is_email(input_str):
    return regex_validate(REGEX_EMAIL, input_str)
    
def is_ip4(input_str):
    return regex_validate(REGEX_IP4, input_str)

def is_ip6(input_str):
    return regex_validate(REGEX_IP6, input_str)

def is_ip(input_str):
    return is_ip4(input_str) or is_ip6(input_str)


def get_permanent_uri_schemes():
    """
    http://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml
    """
    with open('uri-schemes-1.csv', 'rb') as csvfile:
        scheme_reader = csv.reader(csvfile)
        scheme_reader.next()
        valid_schemes = {}
        for row in scheme_reader:
            valid_schemes[row[0]] = '%s %s' % (row[2], row[3])
    return valid_schemes

def get_provisional_uri_schemes():
    """
    http://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml
    """
    with open('uri-schemes-2.csv', 'rb') as csvfile:
        scheme_reader = csv.reader(csvfile)
        scheme_reader.next()
        valid_schemes = {}
        for row in scheme_reader:
            valid_schemes[row[0]] = '%s %s' % (row[2], row[3])
    return valid_schemes


def is_scheme(input_str):
    recognized_schemes = get_provisional_uri_schemes()
    recognized_schemes.update(get_permanent_uri_schemes())
    return input_str in recognized_schemes
    
    
def is_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))
    


def is_uri(input_str):
    """
    https://tools.ietf.org/html/rfc3986
    
    Uniform Resource Identifier (URI) is a string of characters used to 
    identify a name or a resource on the Internet

    A URI identifies a resource either by location, or a name, or both. A 
    URI has two specializations known as URL and URN.
    """
    candidate_uri = re.findall(REGEX_URI, input_str)[0]
    scheme    = candidate_uri[1]
    authority = candidate_uri[3]
    #path      = candidate_uri[4]
    #query     = candidate_uri[6]
    #fragment  = candidate_uri[8]
    response = is_scheme(scheme)
    response = response and (is_hostname(authority) or is_ip(authority))
    return response
    
    
def is_urn(input_str):
    """
    https://www.ietf.org/rfc/rfc2141.txt
    """
    return is_prefixed(input_str, 'urn:')



def is_url(input_str, *args, **kwargs):
    """
    """
    return regex_validate(REGEX_URL, input_str)


def is_zipcode(input_str):
    """ US Zip Code """
    return regex_validate(REGEX_ZIPCODE, input_str)
    
    
    
def is_ABANumber(input_str):
    """for ABA Number (aka Routing Transit Number (RTN)) check digit calculation.
    http://en.wikipedia.org/wiki/Routing_transit_number
    """
    d = input_str
    d = [int(c) for c in d]
    checksum = ( # do the math!
                 7 * (d[0] + d[3] + d[6]) +
                 3 * (d[1] + d[4] + d[7]) +
                 9 * (d[2] + d[5])
               ) % 10
    #print(d[8] == checksum)
    return regex_validate(REGEX_RTN, input_str) and (d[8] == checksum)
    
    
def is_CUSIP(input_str, *args, **kwargs):
    """for CUSIP (North American Securities) check digit calculation.
    """ 
    raise NotImplementedError
    
    
    
def is_EAN13(input_str, *args, **kwargs):
    """EAN-13, UPC, ISBN-13 check digit calculation.
    """
    raise NotImplementedError
    
    
def is_ISBN(input_str, *args, **kwargs):
    """
    ISBN-10 and ISBN-13 check digit calculation.
    """
    raise NotImplementedError
    
    
def is_ISBN10(input_str, *args, **kwargs):
    """
    SBN-10 check digit calculation.
    """
    raise NotImplementedError
    
def is_ISIN(input_str, *args, **kwargs):
    """
    ISIN International Securities Identifying Number check digit calculation.
        """
    raise NotImplementedError


def is_Luhn(input_str, *args, **kwargs):
    """
    Luhn check digit calculation - used by credit cards.
    """
    raise NotImplementedError


def is_Sedol(input_str, *args, **kwargs):
    """
    for SEDOL (UK Securities) check digit calculation.
    """
    raise NotImplementedError
    
    
def is_Verhoeff(input_str, *args, **kwargs):
    """
    Verhoeff (Dihedral) check digit calculation.:
    """
    raise NotImplementedError
    
    
def check_type(input_obj, obj_type):
    """Data Type Check

    A Data Type check simply checks whether the data is a string, integer, 
    float, array and so on. Since a lot of data is received through forms, 
    we can’t blindly use functions such as is_int() since a single form 
    value is going to be a string and may exceed the maximum integer value 
    that PHP natively supports anyway. Neither should we get too creative 
    and habitually turn to regular expressions since this may violate the 
    KISS principle we prefer in designing security.

    """
    return isinstance(input_obj, obj_type)


def check_charset(input_obj, allowed_charset):
    """Allowed Characters Check
    
    The Allowed Characters check simply ensures that a string only contains 
    valid characters. 
    """
    pass


def check_format(input_str, format_str):
    """Format Check

    Format checks ensure that data matches a specific pattern of allowed 
    characters. Emails, URLs and dates are obvious examples here. Best 
    approaches should use PHP’s filter_var() function, the DateTime class 
    and regular expressions for other formats. The more complex a format is, 
    the more you should lean towards proven format checks or syntax checking 
    tools.
    """
    pass


def check_limit():
    """Limit Check
    
    A limit check is designed to test if a value falls within the given range. 
    For example, we may only accept an integer that is greater than 5, or 
    between 0 and 3, or must never be 34. These are all integer limits but a 
    limit check can be applied to string length, file size, image dimensions,
    date ranges, etc.
    """
    pass


def check_presence():
    """Presence Check
    
    The presence check ensures that we don’t proceed using a set of data if it
    omits a required value. A signup form, for example, might require a 
    username, password and email address with other optional details. The 
    input will be invalid if any required data is missing.
    """
    pass


def check_verification():
    """Verification Check
    
    A verification check is when input is required to include two identical 
    values for the purposes of eliminating error. Many signup forms, for 
    example, may require users to type in their requested password twice to 
    avoid any transcription errors. If the two values are identical, the data 
    is valid.
    """
    pass


def check_logic():
    """Logic Check
    
    The logic check is basically an error control where we ensure the data 
    received will not provoke an error or exception in the application. For 
    example, we may be substituting a search string received into a regular
    expression. This might provoke an error on compiling the expression.
    Integers above a certain size may also cause errors, as can zero when we
    try the divide using it, or when we encounter the weirdness 
    of +0, 0 and -0.
    """
    pass

def check_existence():
    """Resource Existence Check
    
    """
    pass
