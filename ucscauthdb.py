# For connecting
from sqlalchemy import create_engine

# For schema/mapped class
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Sequence, DateTime

# For session management
from sqlalchemy.orm import sessionmaker

# For finding distinct country values
from sqlalchemy import distinct

# for counting distinct values in queries
from sqlalchemy import func



import credentials

__Base = declarative_base()

# Database table mapping class
class UCSCAuth(__Base):
    __tablename__ = 'ucscauth'

    id = Column(Integer, Sequence('ucscauth_id_seq'), primary_key=True)
    username = Column(String)
    srcip = Column(String)
    macaddress = Column(String)
    authsource = Column(String)
    authtime = Column(DateTime)
    country = Column(String)
    elasticid = Column(String)

    def __repr__(self):
        return "<ucscauth(username='{0}', srcip='{1}', macaddress='{2}' " \
               "authsource='{3}', authtime='{4}', country='{5}', elasticid='{6}')>".format(self.username, self.srcip, self.macaddress, self.authsource, self.authtime, self.country, self.elasticid)

# Class for handling database transactions
class UCSCAuthDB():
    # global session
    __session = None
    __engine = None

    def connect(self):
        # Set up connection string for postgres DB
        connString = 'postgresql://{0}:{1}@{2}/{3}'.format(credentials.psqluser, credentials.psqlpass,
                                                           credentials.psqlserver, credentials.psqldatabase)
        self.__engine = create_engine(connString)

        # Create the session, store in global
        Session = sessionmaker(bind=self.__engine)
        self.__session = Session()

    
    # Returns all logins over a date range from the authentication database table for one type of authentication source. Calling without authsource will not restrict the query
    # to authentication sources.
    def getUserLoginsForAuthsource(self, nowDate, pastDate, authsource='all'):
        
        if authsource == 'all':
            q = self.__session.query(UCSCAuth.username, func.count(distinct(UCSCAuth.country))).group_by(UCSCAuth.username).having(func.count(distinct(UCSCAuth.country))>2).filter(UCSCAuth.authtime >= pastDate,UCSCAuth.authtime <= nowDate, UCSCAuth.country != 'null', UCSCAuth.country != 'NULL').all()
        else:
            q = self.__session.query(UCSCAuth.username, func.count(distinct(UCSCAuth.country))).group_by(UCSCAuth.username).having(func.count(distinct(UCSCAuth.country))>2).filter(UCSCAuth.authtime >= pastDate,UCSCAuth.authtime <= nowDate, UCSCAuth.country != 'null', UCSCAuth.country != 'NULL', UCSCAuth.authsource == authsource).all()

        # original SQL
        #select username, count(DISTINCT country) as ccount from ucscauth where authtime > '2018-04-23 00:00:00' AND country != 'null' AND country != 'NULL' group by username HAVING count(DISTINCT country) > 1 order by ccount desc;

        return q
    
    # Returns all logins for a specific user over a date range.
    def getUserLoginRowData(self, username, nowDate, pastDate):
        
        q = self.__session.query(UCSCAuth).filter(UCSCAuth.authtime >= pastDate,UCSCAuth.authtime <= nowDate, UCSCAuth.country != 'null', UCSCAuth.country != 'NULL', UCSCAuth.username == username).all()

        #select username, count(DISTINCT country) as ccount from ucscauth where authtime > '2018-04-23 00:00:00' AND country != 'null' AND country != 'NULL' group by username HAVING count(DISTINCT country) > 1 order by ccount desc;

        return q

    def close(self):
        self.__session = None
        self.__engine = None
