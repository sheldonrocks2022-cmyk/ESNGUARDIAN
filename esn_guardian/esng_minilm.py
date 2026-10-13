"""ESNG MiniLM: locally trained, tiny statistical language model.

A bounded word n-gram model trained on bundled, authored examples. It is NOT
a transformer or general-purpose LLM. No remote inference, downloads or keys.
Never trains on user messages, persistent notes, or private Discord content.
"""
from __future__ import annotations
import hashlib
import re
from collections import Counter, defaultdict

CORPUS = (
    ("hello", "Hello. I am ESNG AI, a locally running assistant."),
    ("what can you do", "I can calculate, analyze text, explain supported concepts, and read public sources."),
    ("what are you", "I am a small local language model combined with deterministic tools."),
    ("how do you work", "My language model predicts words from a small bundled training corpus. Specialized tools handle calculations and research."),
    ("are you an llm", "No. My local model is a compact statistical language model, not a large transformer."),
    ("what is a language model", "A language model estimates which words are likely to follow a sequence of words."),
    ("what is probability", "Probability measures how likely an event is, between zero and one."),
    ("what is algebra", "Algebra uses symbols and equations to represent relationships between quantities."),
    ("what is geometry", "Geometry studies shapes, distances, angles, areas, and spatial relationships."),
    ("what is python", "Python is a programming language used for automation, data analysis, and applications."),
    ("what is a variable", "A variable is a name that refers to a value in a program or equation."),
    ("what is a function", "A function is a reusable operation that accepts inputs and may return an output."),
    ("what is a loop", "A loop repeats instructions until a condition or sequence is complete."),
    ("what is debugging", "Debugging means locating, understanding, and correcting errors in a program."),
    ("what is an api", "An API is an interface that allows programs to communicate using defined operations."),
    ("what is privacy", "Privacy involves controlling how personal information is collected, used, and shared."),
    ("what is cybersecurity", "Cybersecurity protects systems and data from unauthorized access and damage."),
    ("what is encryption", "Encryption transforms readable data into encoded data that requires a key to decode."),
    ("what is open source", "Open source software makes its source code available under a license."),
    ("what is research", "Research gathers evidence, compares sources, and distinguishes facts from uncertainty."),
    ("how to check sources", "Compare multiple credible sources, inspect publication dates, and verify claims."),
    ("how to solve problems", "Define the problem, identify constraints, test a small solution, and verify the result."),
    ("how to learn programming", "Start with variables, conditions, loops, functions, and small practical projects."),
    ("how to write clearly", "State the main idea first, use concrete language, and remove unnecessary words."),
    ("how to compare options", "List the requirements, evaluate tradeoffs, and verify the evidence for each option."),
    ("what is an algorithm", "An algorithm is a sequence of steps designed to solve a problem."),
    ("what is a database", "A database organizes information for storage, retrieval, and updates."),
    ("what is machine learning", "Machine learning uses data to fit models that make predictions or decisions."),
    ("what is a neural network", "A neural network learns weighted connections between mathematical processing units."),
    ("what is an ngram", "An n gram is a sequence of adjacent words used in statistical language modeling."),
)
EXTRA_CORPUS = (
    ("what is recursion", "Recursion occurs when a function calls itself with a smaller subproblem and a stopping condition."),
    ("what is a list", "A list is an ordered mutable collection of values in Python."),
    ("what is a dictionary", "A dictionary maps unique keys to values."),
    ("what is a tuple", "A tuple is an ordered immutable sequence in Python."),
    ("what is a class", "A class defines a template for objects with attributes and methods."),
    ("what is an exception", "An exception signals an error or unusual condition during execution."),
    ("what is a traceback", "A traceback lists the call path and location of an exception."),
    ("what is a unit test", "A unit test checks a small piece of software against expected behavior."),
    ("what is continuous integration", "Continuous integration runs automated checks when changes are submitted."),
    ("what is git", "Git is a distributed version control system for tracking code changes."),
    ("what is github", "GitHub hosts Git repositories and supports collaboration and automated workflows."),
    ("what is a branch", "A branch is an independent line of development in a version control repository."),
    ("what is a commit", "A commit records a snapshot of changes in version control."),
    ("what is latency", "Latency is the delay between an action and its response."),
    ("what is ram", "RAM stores data actively used by running programs."),
    ("what is a cpu", "A CPU executes instructions and coordinates computations."),
    ("what is a gpu", "A GPU performs parallel operations useful for graphics and some machine learning."),
    ("what is a server", "A server provides resources or services to other computers over a network."),
    ("what is an ip address", "An IP address identifies a network interface for internet protocol communication."),
    ("what is dns", "DNS translates domain names into network addresses."),
    ("what is https", "HTTPS uses transport encryption to protect web communication."),
    ("what is json", "JSON is a structured text format for exchanging data."),
    ("what is sql", "SQL is a language for querying and modifying relational databases."),
    ("what is a regex", "A regular expression describes patterns for matching text."),
    ("what is statistics", "Statistics analyzes data through summaries, variability, and inference."),
    ("what is a mean", "The mean is the sum of values divided by the number of values."),
    ("what is a median", "The median is the middle value after sorting observations."),
    ("what is a standard deviation", "Standard deviation measures how far values typically vary from their mean."),
    ("what is a hypothesis", "A hypothesis is a testable explanation or prediction."),
    ("what is a citation", "A citation identifies the source supporting a statement."),
    ("what is misinformation", "Misinformation is false or misleading information, whether shared intentionally or not."),
    ("what is a transformer model", "A transformer is a neural network architecture using attention to process sequences."),
    ("what is a token", "A token is a unit of text processed by a language model."),
    ("what is model training", "Model training adjusts parameters or statistical counts using example data."),
    ("what is overfitting", "Overfitting happens when a model learns training examples too closely and generalizes poorly."),
    ("what is inference", "Inference uses an already built model to produce predictions."),
    ("what is a context window", "A context window is the amount of recent input a model can consider."),
    ("what is a hallucination", "A model hallucination is an unsupported or invented answer presented as fact."),
    ("what is source verification", "Source verification checks provenance, credibility, and agreement with independent evidence."),
    ("what is local ai", "Local AI runs inference on hardware controlled by the operator rather than a hosted provider."),
)
WORD = re.compile(r"[a-z0-9']+|[.,!?;:]", re.I)
STOP = frozenset("a an the is are was were to of in on and or it i you me my your do does what how why can".split())

def _words(s: str) -> list[str]:
    return [w for w in WORD.findall(s.lower()) if re.fullmatch(r"[a-z0-9\x27]+", w)][:100]

class ESNGMiniLM:
    """Deterministic tiny trigram model plus conservative corpus retrieval."""
    def __init__(self):
        self.next_words: dict[tuple[str,str], Counter[str]] = defaultdict(Counter)
        self.entries = []
        for question, answer in CORPUS + EXTRA_CORPUS:
            self.entries.append((set(w for w in _words(question) if w not in STOP), answer))
            tokens = ["<s>", "<s>"] + _words(answer) + ["</s>"]
            for i in range(2, len(tokens)):
                self.next_words[(tokens[i-2], tokens[i-1])][tokens[i]] += 1

    def match(self, question: str) -> str | None:
        terms = set(w for w in _words(question) if w not in STOP)
        if not terms: return None
        best_score, best = 0.0, None
        for keywords, answer in self.entries:
            shared = len(terms & keywords)
            score = shared / len(terms | keywords) if shared else 0
            if score > best_score:
                best_score, best = score, answer
        # Require strong topical agreement; otherwise admit uncertainty.
        return best if best_score >= 0.66 else None

    def generate(self, seed: str = "", max_words: int = 36) -> str:
        """Predict a bounded sequence; generated text is NOT factual evidence."""
        max_words = max(1, min(int(max_words), 60))
        state = ("<s>", "<s>")
        output = []
        # Stable seed selection allows reproducible tests without randomness.
        salt = hashlib.sha256(seed.encode("utf-8")[:200]).digest()
        for step in range(max_words):
            candidates = self.next_words.get(state)
            if not candidates: break
            ordered = sorted(candidates.items(), key=lambda item: (-item[1], item[0]))
            total = sum(count for _, count in ordered)
            pick = int.from_bytes(hashlib.sha256(salt + step.to_bytes(2, "big")).digest()[:4], "big") % total
            chosen = ordered[-1][0]
            for token, count in ordered:
                if pick < count:
                    chosen = token
                    break
                pick -= count
            if chosen == "</s>": break
            output.append(chosen)
            state = (state[1], chosen)
        result = " ".join(output)
        result = re.sub(r"\s+([.,!?;:])", r"\1", result)
        return result[:500].capitalize()

    def reply(self, prompt: str) -> str | None:
        p = prompt.strip()[:500]
        if re.fullmatch(r"(?:ai model|language model|model) (?:info|status)", p, re.I):
            return f"ESNG MiniLM: local statistical trigram model; {len(CORPUS) + len(EXTRA_CORPUS)} curated training pairs; no external API; no private-chat training; not a transformer LLM."
        m = re.fullmatch(r"(?:ai generate|model generate)\s*[: ]\s*(.{1,180})", p, re.I | re.S)
        if m:
            return "Experimental local word prediction (not verified facts): " + self.generate(m.group(1))
        return self.match(p) if p.endswith("?") else None
