package dk.sst.oiosaml.wsfed;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.openqa.selenium.lift.Finders.link;

import java.net.URL;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.lift.TestContext;
import org.openqa.selenium.lift.WebDriverTestContext;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.remote.RemoteWebDriver;

public class LoginTest {
	
	private TestContext ctx;
	private WebDriver driver;
	
	@Before
	public void setup() {
		 driver = createDriver();
		ctx = new WebDriverTestContext(driver);
	}
	
	@After
	public void teardown() {
		ctx.quit();
	}

	@Test
	public void testLogin() throws Exception {
		ctx.goTo("http://jre-mac.trifork.com:8080/wsfed/");
		
		ctx.assertPresenceOf(link("Page requiring login"));
		ctx.clickOn(link("Page requiring login"));
		
		ctx.waitFor(link("Log på med testcertifikat"), 2000);
		assertTrue(driver.getCurrentUrl().startsWith("https://testfederation"));
		
		ctx.clickOn(link("Log på med testcertifikat"));
		
		Thread.sleep(1000);
		assertEquals("http://jre-mac.trifork.com:8080/wsfed/sp/priv1.jsp", driver.getCurrentUrl());

		ctx.assertPresenceOf(link("Log out"));
		ctx.clickOn(link("Log out"));
		
		Thread.sleep(1000);
		
		assertTrue(driver.getCurrentUrl().startsWith("https://testfederation"));

		
		ctx.goTo("http://jre-mac.trifork.com:8080/wsfed/");
		ctx.assertPresenceOf(link("Login"));
	}

	protected WebDriver createDriver() {
		try {
			return new RemoteWebDriver(new URL("http://test01.npi.netic.dk:8088/hub"), DesiredCapabilities.internetExplorer());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
