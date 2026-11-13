from copy import deepcopy
from ggsetup.config import example,fingerprint


def configuration(environment='orders',database='OrdersDb',prefix='OR'):
    c=example(environment)
    c['oci']['compartment_id']='ocid1.compartment.oc1..fixture'
    c['source'].update(host='source.example.test',database=database)
    c['target'].update(db_system_id='ocid1.postgresqldbsystem.oc1..fixture',host='target.example.test',database=database)
    c['goldengate']['prefix']=prefix
    return c

def col(name,typ='int',ordinal=1,nullable=False,**extra):
    d={'schema_name':'sales','table_name':'Orders','column_name':name,'ordinal':ordinal,'data_type':typ,
       'is_user_defined':False,'is_assembly_type':False,'max_length':4,'precision':10,'scale':0,
       'is_nullable':nullable,'is_identity':False,'is_computed':False,'is_filestream':False,
       'is_sparse':False,'is_column_set':False,'generated_always_type':0,'encryption_type':None,'is_hidden':False,'computed_expression':None}
    d.update(extra);return d

def key(column='OrderID',ordinal=1,index='PKOrders',primary=True,**extra):
    d={'schema_name':'sales','table_name':'Orders','index_name':index,'is_primary_key':primary,
       'is_unique':True,'is_disabled':False,'has_filter':False,'key_ordinal':ordinal,'is_included_column':False,'column_name':column}
    d.update(extra);return d

def table(schema='sales',name='Orders',**extra):
    d={'schema_name':schema,'table_name':name,'object_id':101,'is_memory_optimized':False,
       'temporal_type':0,'is_filetable':False,'is_tracked_by_cdc':False,'is_external':False,'has_row_security':False}
    d.update(extra);return d

def inspection(c=None):
    c=c or configuration()
    result={'schema_version':1,'report_type':'ggsetup_inspection','configuration_sha256':fingerprint(c),'environment':c['environment'],
        'oci':{'destination':{'status':'ok','data':{'id':c['target']['db_system_id'],'compartment-id':c['oci']['compartment_id']}},
               'connection':{'status':'ok','data':{'primary-db-endpoint':{'fqdn':c['target']['host'],'port':5432}}}},
        'source':{'status':'collected','queries':{}},'target':{'status':'collected','queries':{}}}
    def query(side,name,rows):result[side]['queries'][name]={'status':'ok','rows':rows}
    query('source','identity',[{'database_name':c['source']['database'],'server_name':'SyntheticServer','product_version':'17.0.1','edition':'Developer'}])
    query('source','visibility',[{'view_definition':1,'is_sysadmin':0}])
    query('source','tables',[table()])
    query('source','columns',[col('OrderID',is_identity=True),col('Description','nvarchar',2,True,max_length=80,precision=0),col('Amount','decimal',4,False,precision=19,scale=4,max_length=9)])
    query('source','keys',[key()])
    query('target','identity',[{'database_name':c['target']['database'],'username':'inspector','version_number':'180000','is_standby':False,'encoding':'UTF8'}])
    query('target','tls',[{'ssl':True,'version':'TLSv1.3'}]);query('target','tables',[])
    return result
