ReadMe for oiosaml-authz - Addon for OIOSAML.Java which adds access control based on virk.dk BRS.


General documentation is available in javadoc. See doc/javadoc, the package documentation contains
information on how to install and configure oiosaml-authz.

The distribution contains a demo web application, demo.war, which contains oiosaml.java and oiosaml-authz. This application
can be deployed and configured to test oiosaml-authz. Please note that the application still requires
initial configuration of oiosaml.java. Refer to oiosaml.java for more information at 
http://www.softwareborsen.dk/projekter/softwarecenter/brugerstyring/oio-saml-java



For developers
-----------------------------

The source code is located in Subversion at https://svn.softwareborsen.dk/oiosaml.java/authz/trunk/

The version numbers refer to the Subversion revision where the project was built.

The build process is based on Gant (http://gant.codehaus.org/). To build oiosaml-authz, oiosaml.java must
be built first. oiosaml.java can be found at https://svn.softwareborsen.dk/oiosaml.java/sp/trunk/

First run 'gant publish' in oiosaml.java, then run 'gant build_everything' in oiosaml.authz.
