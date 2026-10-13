"""Regression tests for ESNG local intelligence upgrades."""
import unittest
from esn_guardian.esng_intelligence import synthesize, ConversationContext, explain_python_error

class IntelligenceTests(unittest.TestCase):
    def test_synthesis_attribution(self):
        result=synthesize("What does Python support?",[
            ("https://example.org/a","Python supports reusable functions and modules for organizing programs."),
            ("https://example.org/b","Python supports many libraries used for scientific applications.")
        ])
        self.assertIn("https://example.org/",result)
        self.assertIn("Python supports",result)

    def test_synthesis_no_match(self):
        self.assertIn("couldn't find",synthesize("volcano",[
            ("https://example.org","Python supports reusable functions and modules for organizing programs.")
        ]))

    def test_context_isolated(self):
        context=ConversationContext()
        context.remember((1,2),"Python","A programming language")
        self.assertIn("programming",context.followup((1,2),"repeat that"))
        self.assertIsNone(context.followup((1,3),"repeat that"))

    def test_context_forget(self):
        context=ConversationContext()
        context.remember((1,2),"topic","answer")
        context.forget((1,2))
        self.assertIsNone(context.followup((1,2),"repeat that"))

    def test_error(self):
        self.assertIn("dictionary key",explain_python_error("KeyError: 'foo'"))

    def test_unknown_error(self):
        self.assertIsNone(explain_python_error("No errors here"))

if __name__=="__main__":
    unittest.main()
