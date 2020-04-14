package org.toasterlang.viktorengstrom.test;

import core.Attacker;
import core.AttackStep;
import core.Asset;
import core.Defense;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;

public class TestToaster {

	private class ToasterModel {
		public final Toaster toaster = new Toaster("toaster");
		public final FirstSlot first = new FirstSlot("1stSlot");
		public final SecondSlot second = new SecondSlot("2ndSlot");
		public final Owner alice = new Owner("Alice");
		public Toast toastA;
		public Toast toastB;

		public ToasterModel(boolean toast1, boolean toast2){
			toaster.addOwner(alice);
			toaster.addSlots(first);
			toaster.addSlots(second);

			if(toast1) {
				toastA = new Toast("toast1");
				first.addToast(toastA);
			}

			if(toast2){
				toastB = new Toast("toast2");
				second.addToast(toastB);
			}
		}
	}


	@Test
	@DisplayName("Malicious toasting attempt, empty toaster")
	public void testMaliciousToastingNoBread() {
		System.out.println("Malicious toasting attempt, empty toaster.");
		ToasterModel model = new ToasterModel(false, false);

		Attacker attacker = new Attacker();
		attacker.addAttackPoint(model.toaster.attemptMaliciousToasting);
		attacker.attack();

		model.toaster.maliciousToasting.assertCompromisedInstantaneously();
		model.alice.pwned.assertCompromisedInstantaneously();
	}	

	@Test
	@DisplayName("Malicious toasting attempt, slot 1 full.")
	public void testMaliciousToastingSlot1Only() {
		System.out.println("Malicious toasting attempt, slot 1 full.");
		ToasterModel model = new ToasterModel(true, false);

		Attacker attacker = new Attacker();
		attacker.addAttackPoint(model.toaster.attemptMaliciousToasting);
		attacker.attack();

		model.toaster.maliciousToasting.assertCompromisedInstantaneously();
		model.alice.pwned.assertCompromisedInstantaneously();
	}	

	@Test
	@DisplayName("Malicious toasting attempt, slot 2 full.")
	public void testMaliciousToastingSlot2Only() {
		System.out.println("Malicious toasting attempt, slot 2 full.");
		ToasterModel model = new ToasterModel(false, true);

		Attacker attacker = new Attacker();
		attacker.addAttackPoint(model.toaster.attemptMaliciousToasting);
		attacker.attack();

		model.toaster.maliciousToasting.assertCompromisedInstantaneously();
		model.alice.pwned.assertCompromisedInstantaneously();
	}	

	@Test
	@DisplayName("Malicious toasting attempt, full toaster.")
	public void testMaliciousToastingFullToaster() {
		System.out.println("Malicious toasting attempt, full toaster.");
		ToasterModel model = new ToasterModel(true, true);

		Attacker attacker = new Attacker();
		attacker.addAttackPoint(model.toaster.attemptMaliciousToasting);
		attacker.attack();

		model.toaster.maliciousToasting.assertUncompromised();
		model.alice.pwned.assertUncompromised();
	}	

	@Test
	@DisplayName("Toast removal attempt, empty toaster.")
	public void testToastSabotageEmptyToaster() {
		System.out.println("Toast removal attempt, empty toaster.");
		ToasterModel model = new ToasterModel(false, false);

		Attacker attacker = new Attacker();
		attacker.addAttackPoint(model.toaster.attemptToastSabotage);
		attacker.attack();

		model.toaster.toastRemoval.assertUncompromised();
		model.alice.pwned.assertUncompromised();
	}	

	@Test
	@DisplayName("Toast removal attempt, slot 1 full.")
	public void testToastSabotageSlot1Full() {
		System.out.println("Toast removal attempt, slot 1 full.");
		ToasterModel model = new ToasterModel(true, false);

		Attacker attacker = new Attacker();
		attacker.addAttackPoint(model.toaster.attemptToastSabotage);
		attacker.attack();

		model.toaster.toastRemoval.assertCompromisedInstantaneously();
		model.alice.pwned.assertCompromisedInstantaneously();
		model.toastA.remove.assertCompromisedInstantaneously();
	}	

	@Test
	@DisplayName("Toast removal attempt, slot 2 full.")
	public void testToastSabotageSlot2Full() {
		System.out.println("Toast removal attempt, slot 2 full.");
		ToasterModel model = new ToasterModel(false, true);

		Attacker attacker = new Attacker();
		attacker.addAttackPoint(model.toaster.attemptToastSabotage);
		attacker.attack();

		model.toaster.toastRemoval.assertCompromisedInstantaneously();
		model.alice.pwned.assertCompromisedInstantaneously();
		model.toastB.remove.assertCompromisedInstantaneously();
	}	

	@Test
	@DisplayName("Toast removal attempt, full toaster.")
	public void testToastSabotageFullToaster() {
		System.out.println("Toast removal attempt, full toaster.");
		ToasterModel model = new ToasterModel(true, true);

		Attacker attacker = new Attacker();
		attacker.addAttackPoint(model.toaster.attemptToastSabotage);
		attacker.attack();

		model.toaster.toastRemoval.assertCompromisedInstantaneously();
		model.alice.pwned.assertCompromisedInstantaneously();
		model.toastA.remove.assertCompromisedInstantaneously();
		model.toastB.remove.assertCompromisedInstantaneously();
	}	

	@Test
	@DisplayName("Both attacks, empty toaster.")
	public void testFullAttackEmptyToaster() {
		System.out.println("Both attacks, empty toaster.");
		ToasterModel model = new ToasterModel(false, false);

		Attacker attacker = new Attacker();
		attacker.addAttackPoint(model.toaster.attemptMaliciousToasting);
		attacker.addAttackPoint(model.toaster.attemptToastSabotage);
		attacker.attack();

		model.toaster.toastRemoval.assertUncompromised();
		model.toaster.maliciousToasting.assertCompromisedInstantaneously();
		model.alice.pwned.assertCompromisedInstantaneouslyFrom(model.toaster.maliciousToasting);
	}	


	@Test
	@DisplayName("Both attacks, slot 1 full.")
	public void testFullAttackSlot1Full() {
		System.out.println("Both attacks, slot 1 full.");
		ToasterModel model = new ToasterModel(true, false);

		Attacker attacker = new Attacker();
		attacker.addAttackPoint(model.toaster.attemptMaliciousToasting);
		attacker.addAttackPoint(model.toaster.attemptToastSabotage);
		attacker.attack();

		model.toaster.toastRemoval.assertCompromisedInstantaneously();
		model.toaster.maliciousToasting.assertCompromisedInstantaneously();
		model.alice.pwned.assertCompromisedInstantaneouslyFrom(model.toaster.maliciousToasting);
		model.alice.pwned.assertCompromisedInstantaneouslyFrom(model.toaster.toastRemoval);
		model.toastA.remove.assertCompromisedInstantaneously();
	}	

	@Test
	@DisplayName("Both attacks, slot 2 full.")
	public void testFullAttackSlot2Full() {
		System.out.println("Both attacks, slot 2 full.");
		ToasterModel model = new ToasterModel(false, true);

		Attacker attacker = new Attacker();
		attacker.addAttackPoint(model.toaster.attemptMaliciousToasting);
		attacker.addAttackPoint(model.toaster.attemptToastSabotage);
		attacker.attack();

		model.toaster.toastRemoval.assertCompromisedInstantaneously();
		model.toaster.maliciousToasting.assertCompromisedInstantaneously();
		model.alice.pwned.assertCompromisedInstantaneouslyFrom(model.toaster.maliciousToasting);
		model.alice.pwned.assertCompromisedInstantaneouslyFrom(model.toaster.toastRemoval);
		model.toastB.remove.assertCompromisedInstantaneously();
	}	

	@Test
	@DisplayName("Both attacks, full toaster.")
	// Works as intended. The attacker can only remove toast.
	// The language does not support removing toast -> adding new toast.
	// And time doesn't exist in MAL.
	public void testFullAttackFullToaster() {
		System.out.println("Both attacks, full toaster.");
		ToasterModel model = new ToasterModel(true, true);

		Attacker attacker = new Attacker();
		attacker.addAttackPoint(model.toaster.attemptMaliciousToasting);
		attacker.addAttackPoint(model.toaster.attemptToastSabotage);
		attacker.attack();

		model.toaster.toastRemoval.assertCompromisedInstantaneously();
		model.toaster.maliciousToasting.assertUncompromised();
		model.alice.pwned.assertUncompromisedFrom(model.toaster.maliciousToasting);
		model.alice.pwned.assertCompromisedInstantaneouslyFrom(model.toaster.toastRemoval);
		model.toastA.remove.assertCompromisedInstantaneously();
		model.toastB.remove.assertCompromisedInstantaneously();
	}	

	@AfterEach
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}
}
