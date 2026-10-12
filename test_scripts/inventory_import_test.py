"""Extend the disposable native provisioning fixture; never use production data."""
import pathlib
import sys

extra = r'''
 import urllib.parse
 serial='aa0000000010'
 body={'serialNumber':serial,'name':'Imported-Hall-AP','description':'Imported hall description','deviceType':'','devClass':'venue','venue':venues[0]}
 unit={'name':'Hostname: '+serial,'venue':venues[0],'deviceTypes':['*'],'configuration':[{'name':'Unit hostname','weight':100,'configuration':json.dumps({'unit':{'hostname':'Imported-Hall-AP'}})}]}
 query=urllib.parse.urlencode({'createObjects':json.dumps({'objects':[{'configuration':unit}]})})
 status,created=request('POST','inventory/'+serial+'?'+query,body,True)
 check(status==200,'unknown model with minimal hostname Unit imported status='+str(status)+' error='+str(created.get('ErrorCode')))
 check(created['deviceType']=='' and created['name']==body['name'] and created['description']==body['description'],'untyped name/description persisted')
 check(bool(created['deviceConfiguration']),'per-device hostname Unit referenced')
 status,stored_unit=request('GET','configuration/'+created['deviceConfiguration'],root=True)
 check(status==200 and bool(stored_unit.get('configuration')),'hostname Unit persisted: '+json.dumps(stored_unit))
 check(request('POST','inventory/'+serial,body,True)[0]==400,'existing AP not overwritten')
 bad=dict(body,serialNumber='aa0000000011',deviceType='not-a-real-model')
 check(request('POST','inventory/aa0000000011',bad,True)[0]==400,'supplied invalid model still rejected')
 check(request('POST','inventory/ALPHANUMERIC',dict(body,serialNumber='ALPHANUMERIC'),True)[0]==400,'OEM alphanumeric serial rejected')
 inherited={'unit':{'hostname':'Venue-default','timezone':'UTC','leds-active':False,'location':'Synthetic venue'}}
 shared={'name':'Synthetic inherited unit','venue':venues[0],'deviceTypes':['*'],'configuration':[{'name':'Unit','weight':10,'configuration':json.dumps(inherited)}]}
 status,conf=request('POST','configuration/0',shared,True);check(status==200,'shared Unit created')
 check(conf['id'] in request('GET','venue/'+venues[0],root=True)[1]['configurations'],'shared venue config membership read back')
 status,computed=request('GET','inventory/'+serial+'?config=true&explain=true',root=True)
 current=request('GET','inventory/'+serial,root=True)[1]
 check(status==200 and computed['config']['unit']['hostname']=='Imported-Hall-AP','per-device hostname takes priority: '+json.dumps({'computed':computed,'device':current,'unit':stored_unit}))
 for field in ('timezone','leds-active','location'):
  check(computed['config']['unit'][field]==inherited['unit'][field],'inherited Unit field retained: '+field)
 plain='aa0000000012'
 check(request('POST','inventory/'+plain,dict(body,serialNumber=plain),True)[0]==200,'legacy untyped inventory without a Unit remains supported')
 check(request('GET','inventory/'+plain+'?config=true',root=True)[1]['config']['unit']==inherited['unit'],'non-imported full Unit unchanged')
 check(request('POST','inventory/aa0000000013',dict(body,serialNumber='aa0000000013'))[0]==403,'scoped reader cannot create untyped inventory')
'''
source = pathlib.Path(sys.argv[1]).read_text()
marker = " print('PASS',checks,"
assert marker in source
source = source.replace(marker, extra + marker, 1)
exec(compile(source, sys.argv[1], 'exec'), {'__name__': '__main__'})
