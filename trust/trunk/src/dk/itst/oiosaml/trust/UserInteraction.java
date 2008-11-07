package dk.itst.oiosaml.trust;

public enum UserInteraction {
	NONE("none"),
	IF_NEEDED("InteractIfNeeded");
	
	private final String value;
	
	private UserInteraction(String value) {
		this.value = value;
	}
	
	public String getValue() {
		return value;
	}
}
