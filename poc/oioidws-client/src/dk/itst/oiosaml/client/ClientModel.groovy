package dk.itst.oiosaml.client;

import groovy.beans.Bindable

class ClientModel {
	
	@Bindable String localStsUrl = 'http://localhost:8880/oioidws-localsts/TokenServiceService';
	@Bindable String serviceStsUrl = 'https://login.oioidws.dk/oioidws';
	@Bindable String serviceUrl = 'https://appa.oioidws.dk/service';
	@Bindable String certificatePassword = 'Test1234'
	@Bindable String username = 'jre'
	@Bindable String password = 'dild42'
	
	@Bindable String certificate = '/home/recht/.oces/jre-test.p12'
	
}
