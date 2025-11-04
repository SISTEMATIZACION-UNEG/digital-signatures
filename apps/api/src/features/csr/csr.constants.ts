/**
 * @description The names of the OIDs.
 */
export const OID_NAMES = [
  "commonName",
  "surname",
  "serialNumber",
  "countryName",
  "localityName",
  "emailAddress",
  "stateOrProvinceName",
  "streetAddress",
  "organizationName",
  "organizationalUnitName",
  "title",
  "description",
  "businessCategory",
  "postalCode",
  "givenName",
  "jurisdictionOfIncorporationStateOrProvinceName",
  "jurisdictionOfIncorporationCountryName",
] as const;

/**
 * @description The type of the OID name.
 */
export type OIDName = (typeof OID_NAMES)[number];
