Bindings
-----------------------------------------------------------------------------------

This library contains implementation that upholds the OIO-WSTrust spec, and is 
interoperability tested against the java implementation of OIO-WSTrust spec.

For now, this requires internal Microsoft DLLs for Geneva and WCF to be installed
(System.ServiceModel.dll, System.IdentityModel.dll, Microsoft.IdentityModel.dll).

Contact spn(at)itst.dk to get the private DLLs.


-----------------------------------------------------------------------------------

Contents:

Bindings		Serviceproviderbindings and SecurityTokenServiceBindings that is interoperable with Java

CustomHeaders		LibertyFrameworkHeader, that every serviceprovider must use.

Data			Standard libertyframework fault, and test structure.

Messagecontracts	Test contracts

Serviceinterfaces	Test serviceinterfaces		

TokenClient		Contains code for accessing the STS service using OIO-Trust.

-----------------------------------------------------------------------------------


Installing private DLLs

The private DLLs must be installed in order to use them correctly. For development in
Visual Studio, simply place the files in c:/strtransform/. To run an application
through IIS, the files must be installed in GAC using 

svn.exe -Vr *,*
gacutil /i /r System.IdentityModel.dll
gacutil /i /r System.ServiceModel.dll
gacutil /i /r Microsoft.IdentityModel.dll

These commands must be run from a Visual Studio prompt as Administrator.
