import forge from "node-forge";

/**
 * @description Creates a serial number.
 * @returns The serial number.
 */
export function createSerialNumber() {
  // Generate random bytes.
  const randomBytes = forge.random.getBytesSync(20);

  // Convert to hex string.
  const serialNumber = forge.util.bytesToHex(randomBytes);

  // Ensure the serial number is positive, by checking if the most significant hex digit is 1 (>= 8).
  let mostSignificantHexDigitAsInt = parseInt(serialNumber[0] as string, 16);

  if (mostSignificantHexDigitAsInt < 8) return serialNumber;

  // Convert to positive.
  mostSignificantHexDigitAsInt -= 8;

  return mostSignificantHexDigitAsInt.toString() + serialNumber.substring(1);
}
