from kafka import KafkaProducer
from kafka import KafkaConsumer
import json
from ucscauthdb import UCSCAuthDB
import datetime


# connect to postgres database ()
# if it is not present send an email and alert to the siem ()
ucscauthlogindb = UCSCAuthDB()

# Attempt connection
try:
    ucscauthlogindb.connect()
    print("Connected!")
except Exception as ex:
    raise Exception(ex)

# Connect KafkaProducer
kafkaserver = ["itsec-prod-elk-3.ucsc.edu:9092", "itsec-prod-elk-8.ucsc.edu:9092", "itsec-prod-elk-9.ucsc.edu:9092"]
topic = 'secinc'
try:
    kproducer = KafkaProducer(bootstrap_servers = kafkaserver)
except Exception as ex:
    raise Exception(ex)

# Set up time for data pull
nowDate = datetime.datetime.today().strftime("%Y-%m-%d %H:%M:%S")
pastDate = (datetime.datetime.today() - datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")

authenticationsources = ['shibboleth', 'google', 'vpn']


# Loop through each authentication source and pull records related to potential compromises
for authsource in authenticationsources:

    # Run query for the authentication source
    results = ucscauthlogindb.getUserLoginsForAuthsource(nowDate, pastDate, authsource)

    # Output & build data structure
    for user in results:
        data = {}
        #logRowCount = 1
        logrow = []

        print(user.username)

        data['username'] = str(user.username)
        data['category'] = 'compromised account'
        data['reason'] = 'multi-country geo'
        data['detection_timestamp'] = str(datetime.datetime.today().strftime("%Y-%m-%d %H:%M:%S"))

        userLogins = ucscauthlogindb.getUserLoginRowData(user.username, nowDate, pastDate)
        for row in userLogins:
            #logrow.append(row.elasticid, row.username, row.srcip, row.macaddress, row.authsource, str(row.authtime), row.country)
            #logrow.append(str(row))
            logrow.append("{}, {}, {}, {}, {}, {}, {}".format(row.elasticid, row.username, row.srcip, row.macaddress, row.authsource, str(row.authtime), row.country))
            #data['logrow' + str(logRowCount)] = logrow
            #data['logrow' + str(logRowCount)] = 
            #logRowCount += 1

	data['logrow'] = '\n'.join(logrow)
        print(logrow)
        # Contains users and each user's associated login entries that indicate a potential compromise
        print (str(data) + "\n")

        # Format JSON
        json_data = json.dumps(data)

        # Send to Kafka
        kproducer.send(topic, json_data.encode('utf-8'))
        kproducer.flush()


# DB cleanup
ucscauthlogindb.close()
print("all done.")
