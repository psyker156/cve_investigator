#  This file is part of the cve_investigator, a tool aimed at exploring CVEs
#  Copyright (c) 2025 Philippe Godbout
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

import json
import unittest

import CVE

class TestCVE(unittest.TestCase):

    def test_CVE_loaded_from_external_envelope_string(self):
        """
        This specifically tests the __init__ method when a cve is loaded from a string which
        contains the external envelope (the initial 'cve' tag)
        """
        single_cve = CVE.CVE(RAW_TEST_DATA_WITH_EXTERNAL_ENVELOPE)
        self.assertEqual(single_cve.infos.id, "CVE-2024-12999")

    def test_CVE_loaded_from_external_envelope_json(self):
        """
        This specifically tests the __init__ method when a cve is loaded from a json which
        contains the external envelope (the initial 'cve' tag)
        """
        json_cve = json.loads(RAW_TEST_DATA_WITH_EXTERNAL_ENVELOPE)
        single_cve = CVE.CVE(json_cve)
        self.assertEqual(single_cve.infos.id, "CVE-2024-12999")

    def test_CVE_loaded_from_internal_envelope_string(self):
        """
        This specifically tests the __init__ method when a cve is loaded from a string which
        contains the external envelope (the initial 'cve' tag)
        """
        single_cve = CVE.CVE(RAW_TEST_DATA_WITHOUT_EXTERNAL_ENVELOPE)
        self.assertEqual(single_cve.infos.id, "CVE-2024-12999")

    def test_CVE_loaded_from_internal_envelope_json(self):
        """
        This specifically tests the __init__ method when a cve is loaded from a json which
        contains the external envelope (the initial 'cve' tag)
        """
        json_cve = json.loads(RAW_TEST_DATA_WITHOUT_EXTERNAL_ENVELOPE)
        single_cve = CVE.CVE(json_cve)
        self.assertEqual(single_cve.infos.id, "CVE-2024-12999")

    def test_CVE_invalid_cve(self):
        """
        This specifically tests the __init__ method when a cve is loaded from a json which
        contains the external envelope (the initial 'cve' tag)
        """
        self.assertRaises(ValueError,
                          CVE.CVE,
                          RAW_TEST_DATA_INVALID_CVE)


RAW_TEST_DATA_WITH_EXTERNAL_ENVELOPE = """{"cve":{"id":"CVE-2024-12999","sourceIdentifier":"cna@vuldb.com","published":"2024-12-29T02:15:17.057","lastModified":"2024-12-29T02:15:17.057","vulnStatus":"Received","cveTags":[],"descriptions":[{"lang":"en","value":"A vulnerability has been found in PHPGurukul Small CRM 1.0 and classified as critical. This vulnerability affects unknown code of the file \/admin\/edit-user.php. The manipulation of the argument id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used."}],"metrics":{"cvssMetricV40":[{"source":"cna@vuldb.com","type":"Secondary","cvssData":{"version":"4.0","vectorString":"CVSS:4.0\/AV:N\/AC:L\/AT:N\/PR:L\/UI:N\/VC:L\/VI:L\/VA:L\/SC:N\/SI:N\/SA:N\/E:X\/CR:X\/IR:X\/AR:X\/MAV:X\/MAC:X\/MAT:X\/MPR:X\/MUI:X\/MVC:X\/MVI:X\/MVA:X\/MSC:X\/MSI:X\/MSA:X\/S:X\/AU:X\/R:X\/V:X\/RE:X\/U:X","baseScore":5.3,"baseSeverity":"MEDIUM","attackVector":"NETWORK","attackComplexity":"LOW","attackRequirements":"NONE","privilegesRequired":"LOW","userInteraction":"NONE","vulnerableSystemConfidentiality":"LOW","vulnerableSystemIntegrity":"LOW","vulnerableSystemAvailability":"LOW","subsequentSystemConfidentiality":"NONE","subsequentSystemIntegrity":"NONE","subsequentSystemAvailability":"NONE","exploitMaturity":"NOT_DEFINED","confidentialityRequirements":"NOT_DEFINED","integrityRequirements":"NOT_DEFINED","availabilityRequirements":"NOT_DEFINED","modifiedAttackVector":"NOT_DEFINED","modifiedAttackComplexity":"NOT_DEFINED","modifiedAttackRequirements":"NOT_DEFINED","modifiedPrivilegesRequired":"NOT_DEFINED","modifiedUserInteraction":"NOT_DEFINED","modifiedVulnerableSystemConfidentiality":"NOT_DEFINED","modifiedVulnerableSystemIntegrity":"NOT_DEFINED","modifiedVulnerableSystemAvailability":"NOT_DEFINED","modifiedSubsequentSystemConfidentiality":"NOT_DEFINED","modifiedSubsequentSystemIntegrity":"NOT_DEFINED","modifiedSubsequentSystemAvailability":"NOT_DEFINED","safety":"NOT_DEFINED","automatable":"NOT_DEFINED","recovery":"NOT_DEFINED","valueDensity":"NOT_DEFINED","vulnerabilityResponseEffort":"NOT_DEFINED","providerUrgency":"NOT_DEFINED"}}],"cvssMetricV31":[{"source":"cna@vuldb.com","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1\/AV:N\/AC:L\/PR:L\/UI:N\/S:U\/C:L\/I:L\/A:L","baseScore":6.3,"baseSeverity":"MEDIUM","attackVector":"NETWORK","attackComplexity":"LOW","privilegesRequired":"LOW","userInteraction":"NONE","scope":"UNCHANGED","confidentialityImpact":"LOW","integrityImpact":"LOW","availabilityImpact":"LOW"},"exploitabilityScore":2.8,"impactScore":3.4}],"cvssMetricV2":[{"source":"cna@vuldb.com","type":"Secondary","cvssData":{"version":"2.0","vectorString":"AV:N\/AC:L\/Au:S\/C:P\/I:P\/A:P","baseScore":6.5,"accessVector":"NETWORK","accessComplexity":"LOW","authentication":"SINGLE","confidentialityImpact":"PARTIAL","integrityImpact":"PARTIAL","availabilityImpact":"PARTIAL"},"baseSeverity":"MEDIUM","exploitabilityScore":8.0,"impactScore":6.4,"acInsufInfo":false,"obtainAllPrivilege":false,"obtainUserPrivilege":false,"obtainOtherPrivilege":false,"userInteractionRequired":false}]},"weaknesses":[{"source":"cna@vuldb.com","type":"Primary","description":[{"lang":"en","value":"CWE-74"},{"lang":"en","value":"CWE-89"}]}],"references":[{"url":"https:\/\/phpgurukul.com\/","source":"cna@vuldb.com"},{"url":"https:\/\/vuldb.com\/?ctiid.289660","source":"cna@vuldb.com"},{"url":"https:\/\/vuldb.com\/?id.289660","source":"cna@vuldb.com"},{"url":"https:\/\/vuldb.com\/?submit.469311","source":"cna@vuldb.com"}]}}"""
RAW_TEST_DATA_WITHOUT_EXTERNAL_ENVELOPE = """{"id":"CVE-2024-12999","sourceIdentifier":"cna@vuldb.com","published":"2024-12-29T02:15:17.057","lastModified":"2024-12-29T02:15:17.057","vulnStatus":"Received","cveTags":[],"descriptions":[{"lang":"en","value":"A vulnerability has been found in PHPGurukul Small CRM 1.0 and classified as critical. This vulnerability affects unknown code of the file \/admin\/edit-user.php. The manipulation of the argument id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used."}],"metrics":{"cvssMetricV40":[{"source":"cna@vuldb.com","type":"Secondary","cvssData":{"version":"4.0","vectorString":"CVSS:4.0\/AV:N\/AC:L\/AT:N\/PR:L\/UI:N\/VC:L\/VI:L\/VA:L\/SC:N\/SI:N\/SA:N\/E:X\/CR:X\/IR:X\/AR:X\/MAV:X\/MAC:X\/MAT:X\/MPR:X\/MUI:X\/MVC:X\/MVI:X\/MVA:X\/MSC:X\/MSI:X\/MSA:X\/S:X\/AU:X\/R:X\/V:X\/RE:X\/U:X","baseScore":5.3,"baseSeverity":"MEDIUM","attackVector":"NETWORK","attackComplexity":"LOW","attackRequirements":"NONE","privilegesRequired":"LOW","userInteraction":"NONE","vulnerableSystemConfidentiality":"LOW","vulnerableSystemIntegrity":"LOW","vulnerableSystemAvailability":"LOW","subsequentSystemConfidentiality":"NONE","subsequentSystemIntegrity":"NONE","subsequentSystemAvailability":"NONE","exploitMaturity":"NOT_DEFINED","confidentialityRequirements":"NOT_DEFINED","integrityRequirements":"NOT_DEFINED","availabilityRequirements":"NOT_DEFINED","modifiedAttackVector":"NOT_DEFINED","modifiedAttackComplexity":"NOT_DEFINED","modifiedAttackRequirements":"NOT_DEFINED","modifiedPrivilegesRequired":"NOT_DEFINED","modifiedUserInteraction":"NOT_DEFINED","modifiedVulnerableSystemConfidentiality":"NOT_DEFINED","modifiedVulnerableSystemIntegrity":"NOT_DEFINED","modifiedVulnerableSystemAvailability":"NOT_DEFINED","modifiedSubsequentSystemConfidentiality":"NOT_DEFINED","modifiedSubsequentSystemIntegrity":"NOT_DEFINED","modifiedSubsequentSystemAvailability":"NOT_DEFINED","safety":"NOT_DEFINED","automatable":"NOT_DEFINED","recovery":"NOT_DEFINED","valueDensity":"NOT_DEFINED","vulnerabilityResponseEffort":"NOT_DEFINED","providerUrgency":"NOT_DEFINED"}}],"cvssMetricV31":[{"source":"cna@vuldb.com","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1\/AV:N\/AC:L\/PR:L\/UI:N\/S:U\/C:L\/I:L\/A:L","baseScore":6.3,"baseSeverity":"MEDIUM","attackVector":"NETWORK","attackComplexity":"LOW","privilegesRequired":"LOW","userInteraction":"NONE","scope":"UNCHANGED","confidentialityImpact":"LOW","integrityImpact":"LOW","availabilityImpact":"LOW"},"exploitabilityScore":2.8,"impactScore":3.4}],"cvssMetricV2":[{"source":"cna@vuldb.com","type":"Secondary","cvssData":{"version":"2.0","vectorString":"AV:N\/AC:L\/Au:S\/C:P\/I:P\/A:P","baseScore":6.5,"accessVector":"NETWORK","accessComplexity":"LOW","authentication":"SINGLE","confidentialityImpact":"PARTIAL","integrityImpact":"PARTIAL","availabilityImpact":"PARTIAL"},"baseSeverity":"MEDIUM","exploitabilityScore":8.0,"impactScore":6.4,"acInsufInfo":false,"obtainAllPrivilege":false,"obtainUserPrivilege":false,"obtainOtherPrivilege":false,"userInteractionRequired":false}]},"weaknesses":[{"source":"cna@vuldb.com","type":"Primary","description":[{"lang":"en","value":"CWE-74"},{"lang":"en","value":"CWE-89"}]}],"references":[{"url":"https:\/\/phpgurukul.com\/","source":"cna@vuldb.com"},{"url":"https:\/\/vuldb.com\/?ctiid.289660","source":"cna@vuldb.com"},{"url":"https:\/\/vuldb.com\/?id.289660","source":"cna@vuldb.com"},{"url":"https:\/\/vuldb.com\/?submit.469311","source":"cna@vuldb.com"}]}"""
RAW_TEST_DATA_INVALID_CVE = """{"nooooid":"CVE-2024-12999","sourceIdentifier":"cna@vuldb.com","published":"2024-12-29T02:15:17.057","lastModified":"2024-12-29T02:15:17.057","vulnStatus":"Received","cveTags":[],"descriptions":[{"lang":"en","value":"A vulnerability has been found in PHPGurukul Small CRM 1.0 and classified as critical. This vulnerability affects unknown code of the file \/admin\/edit-user.php. The manipulation of the argument id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used."}],"metrics":{"cvssMetricV40":[{"source":"cna@vuldb.com","type":"Secondary","cvssData":{"version":"4.0","vectorString":"CVSS:4.0\/AV:N\/AC:L\/AT:N\/PR:L\/UI:N\/VC:L\/VI:L\/VA:L\/SC:N\/SI:N\/SA:N\/E:X\/CR:X\/IR:X\/AR:X\/MAV:X\/MAC:X\/MAT:X\/MPR:X\/MUI:X\/MVC:X\/MVI:X\/MVA:X\/MSC:X\/MSI:X\/MSA:X\/S:X\/AU:X\/R:X\/V:X\/RE:X\/U:X","baseScore":5.3,"baseSeverity":"MEDIUM","attackVector":"NETWORK","attackComplexity":"LOW","attackRequirements":"NONE","privilegesRequired":"LOW","userInteraction":"NONE","vulnerableSystemConfidentiality":"LOW","vulnerableSystemIntegrity":"LOW","vulnerableSystemAvailability":"LOW","subsequentSystemConfidentiality":"NONE","subsequentSystemIntegrity":"NONE","subsequentSystemAvailability":"NONE","exploitMaturity":"NOT_DEFINED","confidentialityRequirements":"NOT_DEFINED","integrityRequirements":"NOT_DEFINED","availabilityRequirements":"NOT_DEFINED","modifiedAttackVector":"NOT_DEFINED","modifiedAttackComplexity":"NOT_DEFINED","modifiedAttackRequirements":"NOT_DEFINED","modifiedPrivilegesRequired":"NOT_DEFINED","modifiedUserInteraction":"NOT_DEFINED","modifiedVulnerableSystemConfidentiality":"NOT_DEFINED","modifiedVulnerableSystemIntegrity":"NOT_DEFINED","modifiedVulnerableSystemAvailability":"NOT_DEFINED","modifiedSubsequentSystemConfidentiality":"NOT_DEFINED","modifiedSubsequentSystemIntegrity":"NOT_DEFINED","modifiedSubsequentSystemAvailability":"NOT_DEFINED","safety":"NOT_DEFINED","automatable":"NOT_DEFINED","recovery":"NOT_DEFINED","valueDensity":"NOT_DEFINED","vulnerabilityResponseEffort":"NOT_DEFINED","providerUrgency":"NOT_DEFINED"}}],"cvssMetricV31":[{"source":"cna@vuldb.com","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1\/AV:N\/AC:L\/PR:L\/UI:N\/S:U\/C:L\/I:L\/A:L","baseScore":6.3,"baseSeverity":"MEDIUM","attackVector":"NETWORK","attackComplexity":"LOW","privilegesRequired":"LOW","userInteraction":"NONE","scope":"UNCHANGED","confidentialityImpact":"LOW","integrityImpact":"LOW","availabilityImpact":"LOW"},"exploitabilityScore":2.8,"impactScore":3.4}],"cvssMetricV2":[{"source":"cna@vuldb.com","type":"Secondary","cvssData":{"version":"2.0","vectorString":"AV:N\/AC:L\/Au:S\/C:P\/I:P\/A:P","baseScore":6.5,"accessVector":"NETWORK","accessComplexity":"LOW","authentication":"SINGLE","confidentialityImpact":"PARTIAL","integrityImpact":"PARTIAL","availabilityImpact":"PARTIAL"},"baseSeverity":"MEDIUM","exploitabilityScore":8.0,"impactScore":6.4,"acInsufInfo":false,"obtainAllPrivilege":false,"obtainUserPrivilege":false,"obtainOtherPrivilege":false,"userInteractionRequired":false}]},"weaknesses":[{"source":"cna@vuldb.com","type":"Primary","description":[{"lang":"en","value":"CWE-74"},{"lang":"en","value":"CWE-89"}]}],"references":[{"url":"https:\/\/phpgurukul.com\/","source":"cna@vuldb.com"},{"url":"https:\/\/vuldb.com\/?ctiid.289660","source":"cna@vuldb.com"},{"url":"https:\/\/vuldb.com\/?id.289660","source":"cna@vuldb.com"},{"url":"https:\/\/vuldb.com\/?submit.469311","source":"cna@vuldb.com"}]}"""