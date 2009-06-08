package dk.sst.oiosaml.wsfed;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;

public class Test {

	public static void main(String[] args) {
		WebDriver driver = new FirefoxDriver();
		
		driver.get("http://localhost:8080/wsfed/");
		
		driver.findElement(By.linkText("Page requiring login")).click();
		driver.close();
	}
}
