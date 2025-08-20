#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <memory>
#include <queue>
#include <functional>
#include <unordered_set>
#include <sstream>
#include <lzma.h>

using namespace std;

// Code range allocation for 32-bit codes
namespace CodeRanges {
    const uint32_t WORDS_START = 0x00000000;
    const uint32_t WORDS_END = 0x000FFFFF;           // 1M codes for words
    const uint32_t PHRASES_START = 0x00100000;
    const uint32_t PHRASES_END = 0x0010FFFF;         // 64K codes for phrases
    const uint32_t WILDCARDS_START = 0x00110000;
    const uint32_t WILDCARDS_END = 0x00117FFF;       // 32K codes for wildcards
    const uint32_t LOCAL_START = 0x00118000;
    const uint32_t LOCAL_END = 0x0011FFFF;           // 32K codes for local words
    const uint32_t RESERVED_START = 0x00120000;      // Reserved for future expansion
}

// Define compression modes
enum class CompressionMode {
    SIMPLE,
    WITH_PHRASES,
    WITH_WILDCARD_PHRASES
};

// Helper function to parse mode string
CompressionMode parse_mode(const string& mode_str) {
    string lower_mode = mode_str;
    transform(lower_mode.begin(), lower_mode.end(), lower_mode.begin(), ::tolower);
    
    if (lower_mode == "simple") {
        return CompressionMode::SIMPLE;
    } else if (lower_mode == "phrases" || lower_mode == "with_phrases") {
        return CompressionMode::WITH_PHRASES;
    } else if (lower_mode == "wildcards" || lower_mode == "with_wildcard_phrases" || lower_mode == "wildcard") {
        return CompressionMode::WITH_WILDCARD_PHRASES;
    } else {
        return CompressionMode::SIMPLE; // Default fallback
    }
}

string mode_to_string(CompressionMode mode) {
    switch (mode) {
        case CompressionMode::SIMPLE:
            return "simple";
        case CompressionMode::WITH_PHRASES:
            return "with_phrases";
        case CompressionMode::WITH_WILDCARD_PHRASES:
            return "with_wildcard_phrases";
        default:
            return "unknown";
    }
}

// Define token types
enum class TokenType {
    WORD,
    PHRASE,
    WILDCARD_PHRASE
};

// Structure to represent a token (word, phrase, or wildcard phrase)
struct Token {
    TokenType type;
    string content;  // For words
    vector<string> phrase_words;  // For phrases
    vector<string> wildcard_pattern;  // For wildcard phrases (with WILDCARD markers)
    string wildcard_word;  // The actual wildcard word
    
    Token(const string& word) : type(TokenType::WORD), content(word) {}
    Token(const vector<string>& words) : type(TokenType::PHRASE), phrase_words(words) {
        // Create a string representation for debugging
        stringstream ss;
        for (size_t i = 0; i < words.size(); ++i) {
            if (i > 0) ss << " ";
            ss << words[i];
        }
        content = ss.str();
    }
    Token(const vector<string>& pattern, const string& wildcard) 
        : type(TokenType::WILDCARD_PHRASE), wildcard_pattern(pattern), wildcard_word(wildcard) {
        // Create a string representation for debugging
        stringstream ss;
        for (size_t i = 0; i < pattern.size(); ++i) {
            if (i > 0) ss << " ";
            if (pattern[i] == "WILDCARD") {
                ss << "*" << wildcard << "*";
            } else {
                ss << pattern[i];
            }
        }
        content = ss.str();
    }
    
    string to_string() const {
        return content;
    }
    
    string get_pattern_string() const {
        if (type != TokenType::WILDCARD_PHRASE) return content;
        
        stringstream ss;
        for (size_t i = 0; i < wildcard_pattern.size(); ++i) {
            if (i > 0) ss << " ";
            ss << wildcard_pattern[i];
        }
        return ss.str();
    }
};

// Wildcard phrase structure
struct WildcardPhrase {
    vector<string> pattern;  // Pattern with "WILDCARD" marker
    uint32_t frequency;
    unordered_map<string, uint32_t> wildcard_words;  // Words that fill the wildcard
    
    WildcardPhrase(const vector<string>& pat) : pattern(pat), frequency(0) {}
    
    string to_string() const {
        stringstream ss;
        for (size_t i = 0; i < pattern.size(); ++i) {
            if (i > 0) ss << " ";
            if (pattern[i] == "WILDCARD") {
                ss << "**";
            } else {
                ss << pattern[i];
            }
        }
        return ss.str();
    }
};

struct WordFreq {
    string word;
    uint32_t frequency;

    WordFreq(const string& w, uint32_t f) : word(w), frequency(f) {}

    bool operator<(const WordFreq& other) const {
        return frequency < other.frequency;
    }
};

struct PhraseFreq {
    vector<string> words;
    uint32_t frequency;

    PhraseFreq(const vector<string>& w, uint32_t f) : words(w), frequency(f) {}

    bool operator<(const PhraseFreq& other) const {
        return frequency < other.frequency;
    }

    string to_string() const {
        stringstream ss;
        for (size_t i = 0; i < words.size(); ++i) {
            if (i > 0) ss << " ";
            ss << words[i];
        }
        return ss.str();
    }
};

// Helper functions to determine token type from code
TokenType get_token_type_from_code(uint32_t code) {
    if (code >= CodeRanges::WORDS_START && code <= CodeRanges::WORDS_END) {
        return TokenType::WORD;
    } else if (code >= CodeRanges::PHRASES_START && code <= CodeRanges::PHRASES_END) {
        return TokenType::PHRASE;
    } else if (code >= CodeRanges::WILDCARDS_START && code <= CodeRanges::WILDCARDS_END) {
        return TokenType::WILDCARD_PHRASE;
    } else if (code >= CodeRanges::LOCAL_START && code <= CodeRanges::LOCAL_END) {
        return TokenType::WORD;  // Local words are still words
    } else {
        throw runtime_error("Invalid code: " + to_string(code));
    }
}

bool is_main_word_code(uint32_t code) {
    return code >= CodeRanges::WORDS_START && code <= CodeRanges::WORDS_END;
}

bool is_phrase_code(uint32_t code) {
    return code >= CodeRanges::PHRASES_START && code <= CodeRanges::PHRASES_END;
}

bool is_wildcard_code(uint32_t code) {
    return code >= CodeRanges::WILDCARDS_START && code <= CodeRanges::WILDCARDS_END;
}

bool is_local_word_code(uint32_t code) {
    return code >= CodeRanges::LOCAL_START && code <= CodeRanges::LOCAL_END;
}

// Phrase trie node for efficient phrase lookup
class PhraseNode : public enable_shared_from_this<PhraseNode> {
public:
    unordered_map<uint32_t, shared_ptr<PhraseNode>> children;
    bool is_phrase_end = false;
    uint32_t phrase_code = 0;
    uint32_t phrase_frequency = 0;
    vector<string> phrase_words;

    void insert(const vector<uint32_t>& word_codes, const vector<string>& words, uint32_t pos = 0) {
        if (pos == word_codes.size()) {
            is_phrase_end = true;
            phrase_frequency++;
            phrase_words = words;
            return;
        }

        uint32_t code = word_codes[pos];
        if (children.find(code) == children.end()) {
            children[code] = make_shared<PhraseNode>();
        }

        children[code]->insert(word_codes, words, pos + 1);
    }

    shared_ptr<PhraseNode> find(const vector<uint32_t>& word_codes, uint32_t pos = 0) {
        if (pos == word_codes.size()) {
            return is_phrase_end ? shared_from_this() : nullptr;
        }

        uint32_t code = word_codes[pos];
        auto it = children.find(code);
        if (it == children.end()) {
            return nullptr;
        }

        return it->second->find(word_codes, pos + 1);
    }
};

// Enhanced phrase finder with wildcard support
class PhraseFinder {
private:
    shared_ptr<PhraseNode> root;
    uint32_t min_phrase_freq;
    uint32_t min_phrase_len;
    uint32_t max_phrase_len;
    uint32_t min_wildcard_freq;

public:
    PhraseFinder(uint32_t min_freq = 2, uint32_t min_len = 2, uint32_t max_len = 7, uint32_t min_wildcard = 3)
        : min_phrase_freq(min_freq), min_phrase_len(min_len), max_phrase_len(max_len), min_wildcard_freq(min_wildcard) {
        root = make_shared<PhraseNode>();
    }

    void find_phrases(const vector<string>& tokens,
                      const unordered_map<string, uint32_t>& word_to_code) {
        // Using sliding window to find potential phrases
        for (size_t len = min_phrase_len; len <= max_phrase_len && len <= tokens.size(); ++len) {
            for (size_t i = 0; i <= tokens.size() - len; ++i) {
                vector<uint32_t> word_codes;
                vector<string> phrase_words;

                bool valid_phrase = true;
                for (size_t j = 0; j < len; ++j) {
                    const string& word = tokens[i + j];
                    auto it = word_to_code.find(word);
                    if (it == word_to_code.end()) {
                        valid_phrase = false;
                        break;
                    }
                    word_codes.push_back(it->second);
                    phrase_words.push_back(word);
                }

                if (valid_phrase) {
                    root->insert(word_codes, phrase_words);
                }
            }
        }
    }

    vector<pair<vector<string>, uint32_t>> extract_frequent_phrases() {
        vector<pair<vector<string>, uint32_t>> frequent_phrases;
        extract_frequent_phrases_helper(root, frequent_phrases);

        // Sort by frequency in descending order
        sort(frequent_phrases.begin(), frequent_phrases.end(),
                 [](const auto& a, const auto& b) {
                     return a.second > b.second;
                 });

        return frequent_phrases;
    }

    // New method to find wildcard phrases
    vector<WildcardPhrase> find_wildcard_phrases(const vector<string>& tokens,
                                                const unordered_map<string, uint32_t>& word_to_code) {
        unordered_map<string, WildcardPhrase> wildcard_patterns;

        // Generate wildcard patterns for different lengths
        for (size_t len = min_phrase_len + 1; len <= max_phrase_len && len <= tokens.size(); ++len) {
            // Try placing wildcard at different positions
            for (size_t wildcard_pos = 1; wildcard_pos < len - 1; ++wildcard_pos) {

                // Extract patterns with wildcard at this position
                for (size_t i = 0; i <= tokens.size() - len; ++i) {
                    vector<string> pattern;
                    string wildcard_word = tokens[i + wildcard_pos];

                    // Skip if wildcard word is not in main dictionary
                    if (word_to_code.find(wildcard_word) == word_to_code.end()) {
                        continue;
                    }

                    bool valid_pattern = true;
                    for (size_t j = 0; j < len; ++j) {
                        if (j == wildcard_pos) {
                            pattern.push_back("WILDCARD");
                        } else {
                            const string& word = tokens[i + j];
                            if (word_to_code.find(word) == word_to_code.end()) {
                                valid_pattern = false;
                                break;
                            }
                            pattern.push_back(word);
                        }
                    }

                    if (valid_pattern) {
                        string pattern_key;
                        for (size_t k = 0; k < pattern.size(); ++k) {
                            if (k > 0) pattern_key += " ";
                            pattern_key += pattern[k];
                        }

                        auto it = wildcard_patterns.find(pattern_key);
                        if (it == wildcard_patterns.end()) {
                            it = wildcard_patterns.emplace(pattern_key, WildcardPhrase(pattern)).first;
                        }
                        it->second.frequency++;
                        it->second.wildcard_words[wildcard_word]++;
                    }
                }
            }
        }

        // Filter frequent wildcard patterns
        vector<WildcardPhrase> frequent_wildcards;
        for (const auto& pair : wildcard_patterns) {
            if (pair.second.frequency >= min_wildcard_freq) {
                frequent_wildcards.push_back(pair.second);
            }
        }

        // Sort by frequency
        sort(frequent_wildcards.begin(), frequent_wildcards.end(),
             [](const WildcardPhrase& a, const WildcardPhrase& b) {
                 return a.frequency > b.frequency;
             });

        return frequent_wildcards;
    }

private:
    void extract_frequent_phrases_helper(shared_ptr<PhraseNode> node,
                                        vector<pair<vector<string>, uint32_t>>& phrases) {
        if (!node) return;

        if (node->is_phrase_end && node->phrase_frequency >= min_phrase_freq &&
            node->phrase_words.size() >= min_phrase_len) {
            phrases.push_back({node->phrase_words, node->phrase_frequency});
        }

        for (const auto& child_pair : node->children) {
            extract_frequent_phrases_helper(child_pair.second, phrases);
        }
    }
};

// Simple bit writer for 32-bit codes
class BitWriter {
private:
    vector<uint8_t> buffer;

public:
    void write_uint32(uint32_t value) {
        buffer.push_back((value >> 24) & 0xFF);
        buffer.push_back((value >> 16) & 0xFF);
        buffer.push_back((value >> 8) & 0xFF);
        buffer.push_back(value & 0xFF);
    }

    void write_uint8(uint8_t value) {
        buffer.push_back(value);
    }

    const vector<uint8_t>& get_buffer() const {
        return buffer;
    }

    bool write_to_file(const string& filename) {
        ofstream outfile(filename, ios::binary);
        if (!outfile) return false;
        outfile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        return outfile.good();
    }
};

class BitReader {
private:
    const vector<uint8_t>& buffer;
    size_t current_pos = 0;

public:
    BitReader(const vector<uint8_t>& buf) : buffer(buf) {}

    uint32_t read_uint32() {
        if (current_pos + 4 > buffer.size()) {
            throw runtime_error("BitReader: Not enough data to read uint32");
        }

        uint32_t value = (static_cast<uint32_t>(buffer[current_pos]) << 24) |
                        (static_cast<uint32_t>(buffer[current_pos + 1]) << 16) |
                        (static_cast<uint32_t>(buffer[current_pos + 2]) << 8) |
                        static_cast<uint32_t>(buffer[current_pos + 3]);
        current_pos += 4;
        return value;
    }

    uint8_t read_uint8() {
        if (current_pos >= buffer.size()) {
            throw runtime_error("BitReader: Not enough data to read uint8");
        }
        return buffer[current_pos++];
    }

    bool has_more() const {
        return current_pos < buffer.size();
    }
};

class TwoTierTextCompressor {
private:
    // Main dictionary with 32-bit codes in ranges
    unordered_map<string, uint32_t> main_encode_dict_words;
    unordered_map<string, uint32_t> main_encode_dict_phrases;
    unordered_map<string, uint32_t> main_encode_dict_wildcards;
    vector<string> main_decode_dict_words;
    vector<vector<string>> main_decode_dict_phrases;
    vector<vector<string>> main_decode_dict_wildcards;

    // Local dictionary (for rare words) - uses local range
    unordered_map<string, uint32_t> local_encode_dict;
    vector<string> local_decode_dict;

    // Frequency tracking
    unordered_map<string, uint32_t> word_frequencies;
    vector<PhraseFreq> phrase_frequencies;
    vector<WildcardPhrase> wildcard_frequencies;

    // Compression mode
    CompressionMode compression_mode = CompressionMode::SIMPLE;

    // Settings for phrase detection
    uint32_t min_phrase_freq = 2;
    uint32_t min_phrase_len = 2;
    uint32_t max_phrase_len = 7;
    uint32_t min_wildcard_freq = 3;

    // Preprocessing and tokenization
    vector<string> tokenize(const string& text) {
        vector<string> tokens;
        string current_token;

        for (char c : text) {
            if (isalnum(c) || c == '\'') {
                current_token += tolower(c);
            } else {
                if (!current_token.empty()) {
                    tokens.push_back(current_token);
                    current_token.clear();
                }
                if (!isspace(c)) {
                    tokens.push_back(string(1, c));
                }
            }
        }

        if (!current_token.empty()) {
            tokens.push_back(current_token);
        }

        return tokens;
    }

    // Load dictionary words from file
    vector<string> load_dictionary_words(const string& dict_file) {
        ifstream infile(dict_file);
        if (!infile) {
            cerr << "Error opening dictionary file: " << dict_file << endl;
            return {};
        }

        vector<string> dict_words;
        string word;

        while (getline(infile, word)) {
            if (!word.empty()) {
                transform(word.begin(), word.end(), word.begin(), ::tolower);
                dict_words.push_back(word);
            }
        }

        return dict_words;
    }

    // Modified load_main_dictionary method for new format
    bool load_main_dictionary(const string& dict_file) {
        ifstream infile(dict_file);
        if (!infile) {
            cerr << "Error opening dictionary file: " << dict_file << endl;
            return false;
        }

        string line;
        main_decode_dict_words.clear();
        main_encode_dict_words.clear();
        main_decode_dict_phrases.clear();
        main_encode_dict_phrases.clear();
        main_decode_dict_wildcards.clear();
        main_encode_dict_wildcards.clear();

        // Read header: mode word_count [phrase_count] [wildcard_count]
        if (!getline(infile, line)) {
            cerr << "Error reading dictionary file header" << endl;
            return false;
        }

        istringstream iss(line);
        int mode_int;
        size_t word_count, phrase_count = 0, wildcard_count = 0;

        if (!(iss >> mode_int >> word_count)) {
            cerr << "Error parsing dictionary header" << endl;
            return false;
        }

        compression_mode = static_cast<CompressionMode>(mode_int);

        if (compression_mode == CompressionMode::WITH_PHRASES ||
            compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            iss >> phrase_count;
        }

        if (compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            iss >> wildcard_count;
        }

        // Check dictionary size limits
        if (word_count > (CodeRanges::WORDS_END - CodeRanges::WORDS_START + 1)) {
            cerr << "Error: Word dictionary too large: " << word_count << endl;
            return false;
        }
        if (phrase_count > (CodeRanges::PHRASES_END - CodeRanges::PHRASES_START + 1)) {
            cerr << "Error: Phrase dictionary too large: " << phrase_count << endl;
            return false;
        }
        if (wildcard_count > (CodeRanges::WILDCARDS_END - CodeRanges::WILDCARDS_START + 1)) {
            cerr << "Error: Wildcard dictionary too large: " << wildcard_count << endl;
            return false;
        }

        // Read words and assign codes in word range
        for (size_t i = 0; i < word_count && getline(infile, line); ++i) {
            if (!line.empty()) {
                main_decode_dict_words.push_back(line);
                main_encode_dict_words[line] = CodeRanges::WORDS_START + i;
            }
        }

        // Read phrases and assign codes in phrase range
        if (compression_mode == CompressionMode::WITH_PHRASES ||
            compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            for (size_t i = 0; i < phrase_count && getline(infile, line); ++i) {
                if (!line.empty()) {
                    istringstream phrase_iss(line);
                    string word;
                    vector<string> phrase_words;

                    while (phrase_iss >> word) {
                        phrase_words.push_back(word);
                    }

                    if (!phrase_words.empty()) {
                        main_decode_dict_phrases.push_back(phrase_words);
                        main_encode_dict_phrases[line] = CodeRanges::PHRASES_START + i;
                    }
                }
            }
        }

        // Read wildcards and assign codes in wildcard range
        if (compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            for (size_t i = 0; i < wildcard_count && getline(infile, line); ++i) {
                if (!line.empty()) {
                    istringstream wildcard_iss(line);
                    string word;
                    vector<string> wildcard_pattern;

                    while (wildcard_iss >> word) {
                        wildcard_pattern.push_back(word);
                    }

                    if (!wildcard_pattern.empty()) {
                        main_decode_dict_wildcards.push_back(wildcard_pattern);
                        main_encode_dict_wildcards[line] = CodeRanges::WILDCARDS_START + i;
                    }
                }
            }
        }

        return true;
    }

    // Modified write_main_dictionary method
    bool write_main_dictionary(const string& dict_file) {
        ofstream outfile(dict_file);
        if (!outfile) {
            cerr << "Error opening dictionary file for writing: " << dict_file << endl;
            return false;
        }

        // Write header
        outfile << static_cast<int>(compression_mode) << " " << main_decode_dict_words.size();

        if (compression_mode == CompressionMode::WITH_PHRASES ||
            compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            outfile << " " << main_decode_dict_phrases.size();
        }

        if (compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            outfile << " " << main_decode_dict_wildcards.size();
        }

        outfile << endl;

        // Write words
        for (const auto& word : main_decode_dict_words) {
            outfile << word << endl;
        }

        // Write phrases
        if (compression_mode == CompressionMode::WITH_PHRASES ||
            compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            for (const auto& phrase : main_decode_dict_phrases) {
                for (size_t i = 0; i < phrase.size(); ++i) {
                    if (i > 0) outfile << " ";
                    outfile << phrase[i];
                }
                outfile << endl;
            }
        }

        // Write wildcard patterns
        if (compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            for (const auto& wildcard : main_decode_dict_wildcards) {
                for (size_t i = 0; i < wildcard.size(); ++i) {
                    if (i > 0) outfile << " ";
                    outfile << wildcard[i];
                }
                outfile << endl;
            }
        }

        return outfile.good();
    }

    // Build local dictionary for rare words with range-based codes
    void build_local_dictionary(const vector<string>& rare_words) {
        local_decode_dict.clear();
        local_encode_dict.clear();

        // Check if we have too many rare words
        if (rare_words.size() > (CodeRanges::LOCAL_END - CodeRanges::LOCAL_START + 1)) {
            cerr << "Error: Too many rare words: " << rare_words.size() << endl;
            throw runtime_error("Local dictionary size exceeded");
        }

        for (size_t i = 0; i < rare_words.size(); ++i) {
            local_decode_dict.push_back(rare_words[i]);
            local_encode_dict[rare_words[i]] = CodeRanges::LOCAL_START + i;
        }
    }

    // Detect common phrases in the text
    void detect_phrases(const vector<string>& tokens) {
        if (compression_mode == CompressionMode::SIMPLE) {
            return;
        }

        PhraseFinder finder(min_phrase_freq, min_phrase_len, max_phrase_len, min_wildcard_freq);
        finder.find_phrases(tokens, main_encode_dict_words);

        auto frequent_phrases = finder.extract_frequent_phrases();
        phrase_frequencies.clear();

        for (const auto& phrase_pair : frequent_phrases) {
            phrase_frequencies.push_back(PhraseFreq(phrase_pair.first, phrase_pair.second));
        }

        sort(phrase_frequencies.begin(), phrase_frequencies.end(),
                 [](const PhraseFreq& a, const PhraseFreq& b) {
                     return a.frequency > b.frequency;
                 });

        // Find wildcard phrases
        if (compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            wildcard_frequencies = finder.find_wildcard_phrases(tokens, main_encode_dict_words);
        }

        // Print statistics
        if (compression_mode != CompressionMode::SIMPLE) {
            cout << "Found " << phrase_frequencies.size() << " common phrases:" << endl;
            for (size_t i = 0; i < min(phrase_frequencies.size(), size_t(10)); ++i) {
                cout << phrase_frequencies[i].to_string() << " (Frequency: " << phrase_frequencies[i].frequency << ")" << endl;
            }
        }

        if (compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            cout << "Found " << wildcard_frequencies.size() << " wildcard phrases:" << endl;
            for (size_t i = 0; i < min(wildcard_frequencies.size(), size_t(10)); ++i) {
                cout << wildcard_frequencies[i].to_string() << " (Frequency: " << wildcard_frequencies[i].frequency << ")" << endl;
            }
        }
    }

    // Finds phrases in the tokenized text and returns tokenized result with phrases
    vector<Token> tokenize_with_phrases(const vector<string>& word_tokens) {
        vector<Token> result;

        if (compression_mode == CompressionMode::SIMPLE) {
            for (const auto& word : word_tokens) {
                result.push_back(Token(word));
            }
            return result;
        }

        size_t i = 0;
        while (i < word_tokens.size()) {
            bool phrase_found = false;

            // Try to match wildcard phrases first
            if (compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
                for (const auto& wildcard : wildcard_frequencies) {
                    if (i + wildcard.pattern.size() <= word_tokens.size()) {
                        bool matches = true;
                        string wildcard_word;

                        for (size_t j = 0; j < wildcard.pattern.size(); ++j) {
                            if (wildcard.pattern[j] == "WILDCARD") {
                                wildcard_word = word_tokens[i + j];
                                if (wildcard.wildcard_words.find(wildcard_word) == wildcard.wildcard_words.end()) {
                                    matches = false;
                                    break;
                                }
                            } else {
                                if (word_tokens[i + j] != wildcard.pattern[j]) {
                                    matches = false;
                                    break;
                                }
                            }
                        }

                        if (matches) {
                            result.push_back(Token(wildcard.pattern, wildcard_word));
                            i += wildcard.pattern.size();
                            phrase_found = true;
                            break;
                        }
                    }
                }
            }

            // Try regular phrases
            if (!phrase_found && (compression_mode == CompressionMode::WITH_PHRASES ||
                                 compression_mode == CompressionMode::WITH_WILDCARD_PHRASES)) {
                for (size_t len = min(max_phrase_len, (uint32_t)(word_tokens.size() - i)); len >= min_phrase_len && !phrase_found; --len) {
                    if (i + len <= word_tokens.size()) {
                        vector<string> potential_phrase(word_tokens.begin() + i, word_tokens.begin() + i + len);
                        string phrase_str = potential_phrase[0];
                        for (size_t j = 1; j < potential_phrase.size(); ++j) {
                            phrase_str += " " + potential_phrase[j];
                        }

                        if (main_encode_dict_phrases.find(phrase_str) != main_encode_dict_phrases.end()) {
                            result.push_back(Token(potential_phrase));
                            i += len;
                            phrase_found = true;
                        }
                    }
                }
            }

            if (!phrase_found) {
                result.push_back(Token(word_tokens[i]));
                i++;
            }
        }

        return result;
    }

    // LZMA compression helper
    bool compress_with_lzma(const vector<uint8_t>& input_data, const string& output_file) {
        lzma_stream strm = LZMA_STREAM_INIT;

        lzma_ret ret = lzma_easy_encoder(&strm, 6, LZMA_CHECK_CRC64);
        if (ret != LZMA_OK) {
            cerr << "Error initializing LZMA encoder" << endl;
            return false;
        }

        ofstream outfile(output_file, ios::binary);
        if (!outfile) {
            lzma_end(&strm);
            return false;
        }

        strm.next_in = input_data.data();
        strm.avail_in = input_data.size();

        vector<uint8_t> output_buffer(8192);
        lzma_action action = LZMA_FINISH;

        do {
            strm.next_out = output_buffer.data();
            strm.avail_out = output_buffer.size();

            ret = lzma_code(&strm, action);

            if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
                cerr << "LZMA compression error: " << ret << endl;
                lzma_end(&strm);
                return false;
            }

            size_t bytes_written = output_buffer.size() - strm.avail_out;
            outfile.write(reinterpret_cast<const char*>(output_buffer.data()), bytes_written);

        } while (ret != LZMA_STREAM_END);

        lzma_end(&strm);
        return outfile.good();
    }

    // LZMA decompression helper
    bool decompress_with_lzma(const string& input_file, vector<uint8_t>& output_data) {
        ifstream infile(input_file, ios::binary);
        if (!infile) {
            cerr << "Error opening LZMA file: " << input_file << endl;
            return false;
        }

        lzma_stream strm = LZMA_STREAM_INIT;

        lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, LZMA_CONCATENATED);
        if (ret != LZMA_OK) {
            cerr << "Error initializing LZMA decoder" << endl;
            return false;
        }

        vector<uint8_t> input_buffer(8192);
        vector<uint8_t> output_buffer(8192);
        output_data.clear();

        lzma_action action = LZMA_RUN;

        while (true) {
            if (strm.avail_in == 0 && action == LZMA_RUN) {
                infile.read(reinterpret_cast<char*>(input_buffer.data()), input_buffer.size());
                strm.avail_in = infile.gcount();
                strm.next_in = input_buffer.data();

                if (infile.eof()) {
                    action = LZMA_FINISH;
                }
            }

            strm.next_out = output_buffer.data();
            strm.avail_out = output_buffer.size();

            ret = lzma_code(&strm, action);

            if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
                cerr << "LZMA decompression error: " << ret << endl;
                lzma_end(&strm);
                return false;
            }

            size_t bytes_produced = output_buffer.size() - strm.avail_out;
            output_data.insert(output_data.end(), output_buffer.begin(), output_buffer.begin() + bytes_produced);

            if (ret == LZMA_STREAM_END) {
                break;
            }
        }

        lzma_end(&strm);
        return true;
    }

public:
    TwoTierTextCompressor() = default;

    void set_compression_mode(CompressionMode mode) {
        compression_mode = mode;
    }

    CompressionMode get_compression_mode() const {
        return compression_mode;
    }

    // Compression method with new 32-bit code system
    bool compress(const string& dict_file, const string& input_file, const string& output_file) {
        // Step 1: Load and process input
        ifstream infile(input_file);
        if (!infile) {
            cerr << "Error opening input file: " << input_file << endl;
            return false;
        }

        string text((istreambuf_iterator<char>(infile)), istreambuf_iterator<char>());
        infile.close();

        auto tokens = tokenize(text);

        // Calculate word frequencies
        word_frequencies.clear();
        for (const auto& token : tokens) {
            word_frequencies[token]++;
        }

        // Step 2: Load dictionary words
        auto dict_words = load_dictionary_words(dict_file);
        if (dict_words.empty()) {
            cerr << "Failed to load dictionary words from: " << dict_file << endl;
            return false;
        }

        // Step 3: Build frequency-ordered main dictionary with range-based codes
        vector<WordFreq> word_freq_list;
        for (const auto& word : dict_words) {
            uint32_t freq = 1;
            auto it = word_frequencies.find(word);
            if (it != word_frequencies.end()) {
                freq = it->second;
            }
            word_freq_list.push_back(WordFreq(word, freq));
        }

        sort(word_freq_list.begin(), word_freq_list.end(),
                  [](const WordFreq& a, const WordFreq& b) {
                      return a.frequency > b.frequency;
                  });

        // Check word dictionary size
        if (word_freq_list.size() > (CodeRanges::WORDS_END - CodeRanges::WORDS_START + 1)) {
            cerr << "Error: Word dictionary too large: " << word_freq_list.size() << endl;
            return false;
        }

        // Build main dictionary with range-based codes
        main_decode_dict_words.clear();
        main_encode_dict_words.clear();

        for (size_t i = 0; i < word_freq_list.size(); ++i) {
            main_decode_dict_words.push_back(word_freq_list[i].word);
            main_encode_dict_words[word_freq_list[i].word] = CodeRanges::WORDS_START + i;
        }

        // Step 4: Detect phrases and wildcards
        detect_phrases(tokens);

        // Build dictionaries with range checking
        if (compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            // Check wildcard dictionary size
            if (wildcard_frequencies.size() > (CodeRanges::WILDCARDS_END - CodeRanges::WILDCARDS_START + 1)) {
                cerr << "Error: Wildcard dictionary too large: " << wildcard_frequencies.size() << endl;
                return false;
            }

            // Build wildcard dictionary
            main_decode_dict_wildcards.clear();
            main_encode_dict_wildcards.clear();

            for (size_t i = 0; i < wildcard_frequencies.size(); ++i) {
                const auto& wf = wildcard_frequencies[i];
                main_decode_dict_wildcards.push_back(wf.pattern);
                string pattern_str = "";
                for (size_t j = 0; j < wf.pattern.size(); ++j) {
                    if (j > 0) pattern_str += " ";
                    pattern_str += wf.pattern[j];
                }
                main_encode_dict_wildcards[pattern_str] = CodeRanges::WILDCARDS_START + i;
            }

            // Filter phrases covered by wildcards
            unordered_set<string> phrases_covered_by_wildcards;
            for (const auto& wildcard : wildcard_frequencies) {
                for (const auto& wildcard_word_pair : wildcard.wildcard_words) {
                    vector<string> concrete_phrase;
                    for (const string& pattern_word : wildcard.pattern) {
                        if (pattern_word == "WILDCARD") {
                            concrete_phrase.push_back(wildcard_word_pair.first);
                        } else {
                            concrete_phrase.push_back(pattern_word);
                        }
                    }

                    string phrase_str = concrete_phrase[0];
                    for (size_t i = 1; i < concrete_phrase.size(); ++i) {
                        phrase_str += " " + concrete_phrase[i];
                    }
                    phrases_covered_by_wildcards.insert(phrase_str);
                }
            }

            // Build filtered phrase dictionary
            main_decode_dict_phrases.clear();
            main_encode_dict_phrases.clear();
            size_t phrase_index = 0;

            for (const auto& pf : phrase_frequencies) {
                string phrase_str = pf.to_string();
                if (phrases_covered_by_wildcards.find(phrase_str) == phrases_covered_by_wildcards.end()) {
                    if (phrase_index >= (CodeRanges::PHRASES_END - CodeRanges::PHRASES_START + 1)) {
                        cerr << "Error: Phrase dictionary too large" << endl;
                        return false;
                    }
                    main_decode_dict_phrases.push_back(pf.words);
                    main_encode_dict_phrases[phrase_str] = CodeRanges::PHRASES_START + phrase_index;
                    phrase_index++;
                }
            }

        } else if (compression_mode == CompressionMode::WITH_PHRASES) {
            // Check phrase dictionary size
            if (phrase_frequencies.size() > (CodeRanges::PHRASES_END - CodeRanges::PHRASES_START + 1)) {
                cerr << "Error: Phrase dictionary too large: " << phrase_frequencies.size() << endl;
                return false;
            }

            // Build phrase dictionary
            main_decode_dict_phrases.clear();
            main_encode_dict_phrases.clear();

            for (size_t i = 0; i < phrase_frequencies.size(); ++i) {
                const auto& pf = phrase_frequencies[i];
                main_decode_dict_phrases.push_back(pf.words);
                string phrase_str = pf.to_string();
                main_encode_dict_phrases[phrase_str] = CodeRanges::PHRASES_START + i;
            }
        }

        // Step 5: Handle rare words
        unordered_set<string> rare_words_set;
        for (const auto& token : tokens) {
            if (main_encode_dict_words.find(token) == main_encode_dict_words.end()) {
                rare_words_set.insert(token);
            }
        }

        vector<string> rare_words(rare_words_set.begin(), rare_words_set.end());
        sort(rare_words.begin(), rare_words.end());

        build_local_dictionary(rare_words);

        // Step 6: Write main dictionary
        if (!write_main_dictionary("eng.dict")) {
            cerr << "Failed to write main dictionary file" << endl;
            return false;
        }

        // Step 7: Tokenize with phrases
        auto phrase_tokens = tokenize_with_phrases(tokens);

        // Print statistics
        cout << "\n=== DICTIONARY STATISTICS ===" << endl;
        cout << "Compression mode: " << mode_to_string(compression_mode) << endl;
        cout << "Main dictionary:" << endl;
        cout << "  Words: " << main_decode_dict_words.size() << " (codes 0x" << hex << CodeRanges::WORDS_START << "-0x" << (CodeRanges::WORDS_START + main_decode_dict_words.size() - 1) << dec << ")" << endl;
        if (compression_mode != CompressionMode::SIMPLE) {
            cout << "  Phrases: " << main_decode_dict_phrases.size() << " (codes 0x" << hex << CodeRanges::PHRASES_START << "-0x" << (CodeRanges::PHRASES_START + main_decode_dict_phrases.size() - 1) << dec << ")" << endl;
        }
        if (compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            cout << "  Wildcard patterns: " << main_decode_dict_wildcards.size() << " (codes 0x" << hex << CodeRanges::WILDCARDS_START << "-0x" << (CodeRanges::WILDCARDS_START + main_decode_dict_wildcards.size() - 1) << dec << ")" << endl;
        }
        cout << "Local dictionary:" << endl;
        cout << "  Rare words: " << local_decode_dict.size() << " (codes 0x" << hex << CodeRanges::LOCAL_START << "-0x" << (CodeRanges::LOCAL_START + local_decode_dict.size() - 1) << dec << ")" << endl;

        // Count token usage
        size_t word_count = 0, phrase_count = 0, wildcard_count = 0;
        for (const auto& token : phrase_tokens) {
            switch (token.type) {
                case TokenType::WORD: word_count++; break;
                case TokenType::PHRASE: phrase_count++; break;
                case TokenType::WILDCARD_PHRASE: wildcard_count++; break;
            }
        }

        cout << "\nToken usage:" << endl;
        cout << "  Word tokens: " << word_count << endl;
        if (compression_mode != CompressionMode::SIMPLE) {
            cout << "  Phrase tokens: " << phrase_count << endl;
        }
        if (compression_mode == CompressionMode::WITH_WILDCARD_PHRASES) {
            cout << "  Wildcard tokens: " << wildcard_count << " (each uses 2 codes)" << endl;
        }
        cout << "  Total tokens: " << phrase_tokens.size() << endl;
        cout << "  Total 32-bit codes written: " << (word_count + phrase_count + wildcard_count * 2) << endl;
        cout << "=============================\n" << endl;

        // Step 8: Encode with 32-bit codes
        BitWriter writer;

        // Write header
        writer.write_uint8(static_cast<uint8_t>(compression_mode));
        writer.write_uint32(local_decode_dict.size());

        // Write local dictionary
        for (const auto& word : local_decode_dict) {
            writer.write_uint8(word.length());
            for (char c : word) {
                writer.write_uint8(static_cast<uint8_t>(c));
            }
        }

        // Write number of tokens
        writer.write_uint32(phrase_tokens.size());

        // Encode tokens as 32-bit codes
        for (const auto& token : phrase_tokens) {
            switch (token.type) {
                case TokenType::WORD: {
                    auto it = main_encode_dict_words.find(token.content);
                    if (it != main_encode_dict_words.end()) {
                        writer.write_uint32(it->second);
                    } else {
                        auto local_it = local_encode_dict.find(token.content);
                        if (local_it != local_encode_dict.end()) {
                            writer.write_uint32(local_it->second);
                        } else {
                            cerr << "Error: Word not found in any dictionary: " << token.content << endl;
                            return false;
                        }
                    }
                    break;
                }
                case TokenType::PHRASE: {
                    string phrase_str = token.to_string();
                    auto it = main_encode_dict_phrases.find(phrase_str);
                    if (it != main_encode_dict_phrases.end()) {
                        writer.write_uint32(it->second);
                    } else {
                        cerr << "Error: Phrase not found in dictionary: " << phrase_str << endl;
                        return false;
                    }
                    break;
                }
                case TokenType::WILDCARD_PHRASE: {
                    string pattern_str = token.get_pattern_string();
                    auto it = main_encode_dict_wildcards.find(pattern_str);
                    if (it != main_encode_dict_wildcards.end()) {
                        writer.write_uint32(it->second);

                        // Write wildcard word code
                        auto word_it = main_encode_dict_words.find(token.wildcard_word);
                        if (word_it != main_encode_dict_words.end()) {
                            writer.write_uint32(word_it->second);
                        } else {
                            auto local_it = local_encode_dict.find(token.wildcard_word);
                            if (local_it != local_encode_dict.end()) {
                                writer.write_uint32(local_it->second);
                            } else {
                                cerr << "Error: Wildcard word not found: " << token.wildcard_word << endl;
                                return false;
                            }
                        }
                    } else {
                        cerr << "Error: Wildcard pattern not found: " << pattern_str << endl;
                        return false;
                    }
                    break;
                }
            }
        }

        // Apply LZMA compression
        const vector<uint8_t>& compressed_data = writer.get_buffer();
        string xz_output_file = output_file + ".xz";
        if (!compress_with_lzma(compressed_data, xz_output_file)) {
            cerr << "Error applying LZMA compression" << endl;
            return false;
        }

        cout << "LZMA compressed file written to: " << xz_output_file << endl;

        // Print compression statistics
        ifstream original(input_file, ios::binary | ios::ate);
        size_t original_size = original.tellg();
        original.close();

        ifstream compressed(xz_output_file, ios::binary | ios::ate);
        size_t compressed_size = compressed.tellg();
        compressed.close();

        cout << "Compression completed successfully!" << endl;
        cout << "Original size: " << (double)original_size / 1024 << " Kbytes" << endl;
        cout << "Compressed size: " << (double)compressed_size / 1024 << " Kbytes" << endl;
        cout << "Compression ratio: " << (double)original_size / compressed_size << endl;
        cout << "Space saved: " << (1.0 - (double)compressed_size / original_size) * 100 << "%" << endl;

        return true;
    }

    // Decompression method with new 32-bit code system
    bool decompress(const string& dict_file, const string& input_file, const string& output_file) {
        // Step 1: Load main dictionary
        if (!load_main_dictionary(dict_file)) {
            cerr << "Failed to load main dictionary" << endl;
            return false;
        }

        // Step 2: Decompress LZMA file
        vector<uint8_t> buffer;
        if (!decompress_with_lzma(input_file, buffer)) {
            cerr << "Error decompressing LZMA file" << endl;
            return false;
        }

        BitReader reader(buffer);

        // Step 3: Read header
        compression_mode = static_cast<CompressionMode>(reader.read_uint8());
        uint32_t local_dict_size = reader.read_uint32();

        cout << "Decompressing with mode: " << mode_to_string(compression_mode) << endl;

        // Step 4: Read local dictionary
        local_decode_dict.clear();
        local_encode_dict.clear();

        for (uint32_t i = 0; i < local_dict_size; ++i) {
            uint8_t word_length = reader.read_uint8();
            string word;

            for (uint8_t j = 0; j < word_length; ++j) {
                word += static_cast<char>(reader.read_uint8());
            }

            local_decode_dict.push_back(word);
        }

        // Step 5: Read and decode tokens
        uint32_t num_tokens = reader.read_uint32();

        ofstream outfile(output_file);
        if (!outfile) {
            cerr << "Error opening output file: " << output_file << endl;
            return false;
        }

        bool first_token = true;
        for (uint32_t i = 0; i < num_tokens; ++i) {
            uint32_t code = reader.read_uint32();

            if (!first_token) {
                outfile << " ";
            }
            first_token = false;

            if (is_main_word_code(code)) {
                uint32_t word_index = code - CodeRanges::WORDS_START;
                if (word_index < main_decode_dict_words.size()) {
                    string word = main_decode_dict_words[word_index];

                    // Don't add space before punctuation
                    if (word.length() == 1 && !isalnum(word[0])) {
                        outfile.seekp(-1, ios::cur);
                    }

                    outfile << word;
                } else {
                    cerr << "Error: Invalid main word code: " << code << endl;
                    return false;
                }
            } else if (is_local_word_code(code)) {
                uint32_t word_index = code - CodeRanges::LOCAL_START;
                if (word_index < local_decode_dict.size()) {
                    outfile << local_decode_dict[word_index];
                } else {
                    cerr << "Error: Invalid local word code: " << code << endl;
                    return false;
                }
            } else if (is_phrase_code(code)) {
                uint32_t phrase_index = code - CodeRanges::PHRASES_START;
                if (phrase_index < main_decode_dict_phrases.size()) {
                    const auto& phrase = main_decode_dict_phrases[phrase_index];
                    for (size_t j = 0; j < phrase.size(); ++j) {
                        if (j > 0) outfile << " ";
                        outfile << phrase[j];
                    }
                } else {
                    cerr << "Error: Invalid phrase code: " << code << endl;
                    return false;
                }
            } else if (is_wildcard_code(code)) {
                uint32_t wildcard_index = code - CodeRanges::WILDCARDS_START;
                if (wildcard_index < main_decode_dict_wildcards.size()) {
                    const auto& pattern = main_decode_dict_wildcards[wildcard_index];

                    // Read the wildcard word code
                    uint32_t wildcard_word_code = reader.read_uint32();
                    string wildcard_word;

                    if (is_main_word_code(wildcard_word_code)) {
                        uint32_t word_index = wildcard_word_code - CodeRanges::WORDS_START;
                        if (word_index < main_decode_dict_words.size()) {
                            wildcard_word = main_decode_dict_words[word_index];
                        } else {
                            cerr << "Error: Invalid wildcard main word code: " << wildcard_word_code << endl;
                            return false;
                        }
                    } else if (is_local_word_code(wildcard_word_code)) {
                        uint32_t word_index = wildcard_word_code - CodeRanges::LOCAL_START;
                        if (word_index < local_decode_dict.size()) {
                            wildcard_word = local_decode_dict[word_index];
                        } else {
                            cerr << "Error: Invalid wildcard local word code: " << wildcard_word_code << endl;
                            return false;
                        }
                    } else {
                        cerr << "Error: Invalid wildcard word code: " << wildcard_word_code << endl;
                        return false;
                    }

                    // Output pattern with wildcard substituted
                    for (size_t j = 0; j < pattern.size(); ++j) {
                        if (j > 0) outfile << " ";
                        if (pattern[j] == "WILDCARD") {
                            outfile << wildcard_word;
                        } else {
                            outfile << pattern[j];
                        }
                    }
                } else {
                    cerr << "Error: Invalid wildcard pattern code: " << code << endl;
                    return false;
                }
            } else {
                cerr << "Error: Unknown code: " << code << endl;
                return false;
            }
        }

        outfile.close();
        cout << "Decompression completed successfully!" << endl;
        return true;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 5) {
        cout << "Usage: " << argv[0] << " <mode> -m <compression_mode> <dict_file> <input_file> [output_file]" << endl;
        cout << "Modes:" << endl;
        cout << "  -c: Compress text file" << endl;
        cout << "  -d: Decompress compressed file" << endl;
        cout << "Compression modes (-m flag):" << endl;
        cout << "  simple: Word-only compression" << endl;
        cout << "  phrases: Include phrase compression" << endl;
        cout << "  wildcards: Include phrase and wildcard phrase compression" << endl;
        cout << "Examples:" << endl;
        cout << "  " << argv[0] << " -c -m simple english_words.txt input.txt compressed.bin" << endl;
        cout << "  " << argv[0] << " -c -m phrases english_words.txt input.txt compressed.bin" << endl;
        cout << "  " << argv[0] << " -c -m wildcards english_words.txt input.txt compressed.bin" << endl;
        cout << "  " << argv[0] << " -d eng.dict compressed.bin output.txt" << endl;
        return 1;
    }

    string mode = argv[1];
    TwoTierTextCompressor compressor;

    if (mode == "-c") {
        if (argc < 6 || string(argv[2]) != "-m") {
            cerr << "Error: Compression mode requires -m flag and compression mode specification" << endl;
            return 1;
        }

        string compression_mode_str = argv[3];
        string dict_file = argv[4];
        string input_file = argv[5];
        string output_file;

        if (argc >= 7) {
            output_file = argv[6];
        } else {
            output_file = input_file + ".pz";
        }

        CompressionMode comp_mode = parse_mode(compression_mode_str);
        compressor.set_compression_mode(comp_mode);

        cout << "Compressing file: " << input_file << endl;
        cout << "Dictionary file: " << dict_file << endl;
        cout << "Compression mode: " << mode_to_string(comp_mode) << endl;
        cout << "Output file: " << output_file << endl;

        if (compressor.compress(dict_file, input_file, output_file)) {
            cout << "Compression successful!" << endl;
        } else {
            cout << "Compression failed!" << endl;
            return 1;
        }
    } else if (mode == "-d") {
        string dict_file = argv[2];
        string input_file = argv[3];
        string output_file;

        if (argc >= 5) {
            output_file = argv[4];
        } else {
            output_file = input_file + ".txt";
        }

        cout << "Decompressing file: " << input_file << endl;
        cout << "Output file: " << output_file << endl;

        if (compressor.decompress(dict_file, input_file, output_file)) {
            cout << "Decompression successful!" << endl;
        } else {
            cout << "Decompression failed!" << endl;
            return 1;
        }
    } else {
        cout << "Invalid mode: " << mode << endl;
        cout << "Use -c for compression or -d for decompression" << endl;
        return 1;
    }

    return 0;
}
