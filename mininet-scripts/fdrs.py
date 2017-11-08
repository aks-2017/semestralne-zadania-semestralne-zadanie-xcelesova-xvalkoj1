import sys
from beautifultable import BeautifulTable
from netaddr import valid_ipv4

def add_rule(rulesdict):
    print ('Follow guide for adding rules\n')
    source_ip = check_source_ip('a')
    dest_ip = check_dest_ip('a')
    action = check_action('a')
    protocol = check_protocol('a')

    key = (source_ip,dest_ip)
    data = (action,protocol)

    if key not in rulesdict:
        rulesdict[key] = [data]
        print('\nRule successfully stored\n')
    elif data not in rulesdict[key]:
        rulesdict[key].append(data)
        print('\nRule successfully stored\n')
    else:
        print('\nSame rule already exist\n')

def show_rule(rulesdict):
    table = BeautifulTable()
    if not rulesdict:
        print 'There are not any rules stored'
    else:
        print ('These are our stored rules')
        table.column_headers = ["Source IP", "Destination IP", "Permit/Deny", "Protocol"]
        for key in rulesdict:
            for i in rulesdict[key]:
                table.append_row([key[0], key[1], i[0], i[1]])
        print table

def check_source_ip(flag):
    while True:
        source_ip = raw_input('Source IP add: ')
        if not source_ip:
            if flag == 'f':
                return source_ip
            print 'Not a valid IP address !'
        elif valid_ipv4(source_ip):
            return source_ip
        else:
            print 'Not a valid IP address !'

def check_dest_ip(flag):
    while True:
        dest_ip = raw_input('Destination IP add: ')
        if not dest_ip:
            if flag == 'f':
                return dest_ip
            print 'Not a valid IP address !'
        elif valid_ipv4(dest_ip):
            return dest_ip
        else:
            print 'Not a valid IP address !'

def check_action(flag):
    while True:
        action = raw_input('Permit or Deny [P/D] ').upper()

        if action == 'P' or action == 'D':
            return action
        elif not action:
            if flag == 'f':
                return action
            else:
                print 'Incorrenct input !'
        else:
            print 'Incorrect input !'

def check_protocol(flag):
    while True:
        protocol = raw_input('IP/ICMP/TCP/UDP/HTTP:').upper()
        if protocol == "IP" or protocol == "ICMP" or protocol == "TCP" or protocol == "UDP" or protocol == "HTTP":
            return protocol
        elif not protocol:
            if flag == 'f':
                return protocol
            else:
                print 'Incorrenct input !'
        else:
            print 'Incorrenct input !'

def remove_rule(rulesdict):
    source_ip = check_source_ip()
    dest_ip = check_dest_ip()
    action = check_action()
    protocol = raw_input('IP/ICMP/TCP/UDP/HTTP:')

    if not source_ip and not dest_ip and not action and not protocol:
        print 'Please specify at least one atribute.'

    #Input: Source IP not destination IP
    elif source_ip and not dest_ip:
        for items in rulesdict.keys():
            if source_ip in items[0]:
                find_value_for_delete(items, rulesdict, action, protocol)

    # Input: Destination IP not source IP
    elif dest_ip and not source_ip:
        for items in rulesdict.keys():
            if dest_ip in items[1]:
                find_value_for_delete(items, rulesdict, action, protocol)

    #Input: Source and destination IP
    elif source_ip and dest_ip:
        for items in rulesdict.keys():
            if source_ip in items[0] and dest_ip in items[1]:
                find_value_for_delete(items, rulesdict, action, protocol)

    #Input: Action or protocol
    else:
        for items in rulesdict.keys():
            values_check_for_delete(items, rulesdict, action, protocol)

def find_value_for_delete(items, rulesdict, action, protocol):
    if action or protocol:
        values_check_for_delete(items, rulesdict, action, protocol)
    else:
        for data in rulesdict[items]:
            delete_value(items, rulesdict, data)

def values_check_for_delete(items, rulesdict,action, protocol):
    for data in rulesdict[items]:
        if action in data[0] and protocol in data[1]:
            delete_value(items, rulesdict, data)
        elif action in data[0] and not protocol:
            delete_value(items, rulesdict, data)
        elif not action and protocol in data[1]:
            delete_value(items, rulesdict, data)

def delete_value(items, rulesdict, data):
    print items[0], items[1], data[0], data[1]
    flag = raw_input('Do you want to delete [Y/N] ')
    if flag == 'Y' or flag == 'y':
        rulesdict[items].remove(data)
        print 'Deleted !'

def find_rule(rulesdict):
    source_ip = check_source_ip('f')
    dest_ip = check_dest_ip('f')
    action = check_action('f')
    protocol = check_protocol('f')

    table = BeautifulTable()
    table.column_headers = ["Source IP", "Destination IP", "Permit/Deny", "Protocol"]

    if not source_ip and not dest_ip and not action and not protocol:
        print 'Please specify at least one atribute.'

    # Input: Source IP not destination IP
    elif source_ip and not dest_ip:
        for items in rulesdict.keys():
            if source_ip in items[0]:
                find_value(items, rulesdict, action, protocol, table)

    # Input: Destination IP not source IP
    elif dest_ip and not source_ip:
        for items in rulesdict.keys():
            if dest_ip in items[1]:
                find_value(items, rulesdict, action, protocol, table)

    # Input: Source and destination IP
    elif source_ip and dest_ip:
        for items in rulesdict.keys():
            if source_ip in items[0] and dest_ip in items[1]:
                find_value(items, rulesdict, action, protocol, table)

    # Input: Action or protocol
    else:
        for items in rulesdict.keys():
            values_check(items, rulesdict, action, protocol, table)

    print table


def find_value(items, rulesdict, action, protocol,table):
    if action or protocol:
        values_check(items, rulesdict, action, protocol, table)
    else:
        for data in rulesdict[items]:
            table.append_row([items[0], items[1], data[0], data[1]])


def values_check(items, rulesdict,action, protocol, table):
    for data in rulesdict[items]:
        if action in data[0] and protocol in data[1]:
            table.append_row([items[0], items[1], data[0], data[1]])
        elif action in data[0] and not protocol:
            table.append_row([items[0], items[1], data[0], data[1]])
        elif not action and protocol in data[1]:
            table.append_row([items[0], items[1], data[0], data[1]])

def main():
    rulesdict = {}

    #Hard coded data just for info
    key = ('1.1.1.1', '2.2.2.2')
    data = ('P', 'IP')
    rulesdict[key] = [data]

    key = ('1.1.1.1', '2.2.2.2')
    data = ('D', 'UDP')
    rulesdict[key].append(data)

    key = ('192.168.10.3', '100.20.20.2')
    data = ('D', 'HTTP')
    rulesdict[key] = [data]

    while(1):
        prepinac = raw_input('\nWrite required command or -h for help\n')

        if 'h' in prepinac:
            print ('Select from these commands:\n\t-a\tadd rule to firewall\n\t-r\tremove rule from firewall\n\t-s\tshow all rules\n\t-f\tfind rule\n\t-x\texit\n')
        elif 'a' in prepinac:
            add_rule(rulesdict)
        elif 'r' in prepinac:
            remove_rule(rulesdict)
        elif 's' in prepinac:
            show_rule(rulesdict)
        elif 'f' in prepinac:
            find_rule(rulesdict)
        elif 'x' in prepinac:
            print ('Successfully finished')
            sys.exit()
        else:
            print ('WARNING: Unrecognized command\n')


print ('***  ***  ***  ***  ***  ***  ***  ***  ***  ***  ***  ***')
print ('*********************** Firewall *************************')
print ('***  ***  ***  ***  ***  ***  ***  ***  ***  ***  ***  ***\n')

main()

#TODO reading from file, storing to file (?)

