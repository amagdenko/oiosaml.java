package dk.sst.oiosaml.wsfed;

import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.remote.RemoteWebDriver;

public class Test {

	public static void main(String[] args) throws MalformedURLException, Exception {
//		WebDriver driver = new FirefoxDriver();
		WebDriver driver = new RemoteWebDriver(new URL("http://test01.npi.netic.dk:8088/hub"), DesiredCapabilities.firefox());
		try {
			driver.get("http://jre-mac.trifork.com:8080/wsfed/");

			driver.findElement(By.linkText("Page requiring login")).click();

			Thread.sleep(100000);
			System.out.println(driver.findElements(By.tagName("a")));
			for (WebElement e : driver.findElements(By.tagName("a"))) {
				System.out.println(e.getValue());
			}
//			driver.findElement(By.linkText("Log på med testcertifikat")).click();
			
			System.out.println(driver.getCurrentUrl());
			
		} finally {
			driver.close();
		}
	}
	
	@org.junit.Test
	public void success() {
		assertTrue(true);
	}
}
