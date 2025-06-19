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
#include <experimental/filesystem>

using namespace std;

// Define token types
enum class TokenType {
    WORD,
    PHRASE
};

// Structure to represent a token (word or phrase)
struct Token {
    TokenType type;
    string content;  // For words
    vector<string> phrase_words;  // For phrases
    
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
    
    string to_string() const {
        return content;
    }
};

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

// Phrase finder
class PhraseFinder {
private:
    shared_ptr<PhraseNode> root;
    uint32_t min_phrase_freq;
    uint32_t min_phrase_len;
    uint32_t max_phrase_len;
    
public:
    PhraseFinder(uint32_t min_freq = 2, uint32_t min_len = 2, uint32_t max_len = 7) 
        : min_phrase_freq(min_freq), min_phrase_len(min_len), max_phrase_len(max_len) {
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

class BitWriter {
private:
    vector<uint8_t> buffer;
    uint8_t current_byte = 0;
    uint8_t bits_used = 0;
    
public:
    void write_bits(uint32_t value, uint8_t bit_count) {
        while (bit_count > 0) {
            uint8_t bits_to_write = std::min(bit_count, static_cast<uint8_t>(8 - bits_used));
            uint8_t mask = (1 << bits_to_write) - 1;
            uint8_t bits = (value >> (bit_count - bits_to_write)) & mask;
            
            current_byte |= bits << (8 - bits_used - bits_to_write);
            bits_used += bits_to_write;
            bit_count -= bits_to_write;
            
            if (bits_used == 8) {
                buffer.push_back(current_byte);
                current_byte = 0;
                bits_used = 0;
            }
        }
    }
    
    void flush() {
        if (bits_used > 0) {
            buffer.push_back(current_byte);
            current_byte = 0;
            bits_used = 0;
        }
    }
    
    const vector<uint8_t>& get_buffer() const {
        return buffer;
    }
    
    bool write_to_file(const string& filename) {
        flush();
        ofstream outfile(filename, ios::binary);
        if (!outfile) return false;
        outfile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        return outfile.good();
    }
};

class BitReader {
private:
    const vector<uint8_t>& buffer;
    size_t current_byte_idx = 0;
    uint8_t bits_read = 0;
    
public:
    BitReader(const vector<uint8_t>& buf) : buffer(buf) {}
    
    uint32_t read_bits(uint8_t bit_count) {
        uint32_t result = 0;
        
        while (bit_count > 0 && current_byte_idx < buffer.size()) {
            uint8_t bits_to_read = std::min(bit_count, static_cast<uint8_t>(8 - bits_read));
            uint8_t mask = ((1 << bits_to_read) - 1) << (8 - bits_read - bits_to_read);
            uint8_t bits = (buffer[current_byte_idx] & mask) >> (8 - bits_read - bits_to_read);
            
            result = (result << bits_to_read) | bits;
            bits_read += bits_to_read;
            bit_count -= bits_to_read;
            
            if (bits_read == 8) {
                current_byte_idx++;
                bits_read = 0;
            }
        }
        
        return result;
    }
    
    bool has_more() const {
        return current_byte_idx < buffer.size() || bits_read < 8;
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

class TwoTierTextCompressor {
private:
    // Main dictionary for words and phrases
    unordered_map<string, uint32_t> main_encode_dict_words;
    unordered_map<string, uint32_t> main_encode_dict_phrases;
    vector<string> main_decode_dict_words;
    vector<vector<string>> main_decode_dict_phrases;
    uint8_t main_max_bit_length = 0;
    
    // Local dictionary (for rare words)
    unordered_map<string, uint32_t> local_encode_dict;
    vector<string> local_decode_dict;
    uint8_t local_max_bit_length = 0;
    
    // Frequency tracking
    unordered_map<string, uint32_t> word_frequencies;
    vector<PhraseFreq> phrase_frequencies;
    
    // Settings for phrase detection
    uint32_t min_phrase_freq = 2;  // Minimum frequency for phrases
    uint32_t min_phrase_len = 2;   // Minimum words in a phrase
    uint32_t max_phrase_len = 7;   // Maximum words in a phrase
    
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
    
    // Load dictionary words from file (just the list of words)
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
                // Convert to lowercase for consistency
                transform(word.begin(), word.end(), word.begin(), ::tolower);
                dict_words.push_back(word);
            }
        }
        
        return dict_words;
    }
    
    // Load main dictionary for decompression
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
        
        // First line contains the number of words and phrases
        if (!getline(infile, line)) {
            cerr << "Error reading dictionary file header" << endl;
            return false;
        }
        
        istringstream iss(line);
        size_t word_count, phrase_count;
        if (!(iss >> word_count >> phrase_count)) {
            cerr << "Error parsing dictionary counts" << endl;
            return false;
        }
        
        // Read words
        for (size_t i = 0; i < word_count && getline(infile, line); ++i) {
            if (!line.empty()) {
                main_decode_dict_words.push_back(line);
                main_encode_dict_words[line] = i;
            }
        }
        
        // Read phrases
        for (size_t i = 0; i < phrase_count && getline(infile, line); ++i) {
            if (!line.empty()) {
                istringstream phrase_iss(line);
                string word;
                vector<string> phrase_words;
                
                while (phrase_iss >> word) {
                    phrase_words.push_back(word);
                }
                
                if (!phrase_words.empty()) {
                    string phrase_str = line;
                    main_decode_dict_phrases.push_back(phrase_words);
                    main_encode_dict_phrases[phrase_str] = i;
                }
            }
        }
        
        // Calculate bits needed for main dictionary (words + phrases)
        main_max_bit_length = 0;
        size_t total_entries = main_decode_dict_words.size() + main_decode_dict_phrases.size();
        while ((1ULL << main_max_bit_length) < total_entries) {
            main_max_bit_length++;
        }
        
        return true;
    }
    
    // Write main dictionary to a file
    bool write_main_dictionary(const string& dict_file) {
        ofstream outfile(dict_file);
        if (!outfile) {
            cerr << "Error opening dictionary file for writing: " << dict_file << endl;
            return false;
        }
        
        // Write header with counts
        outfile << main_decode_dict_words.size() << " " << main_decode_dict_phrases.size() << endl;
        
        // Write words
        for (const auto& word : main_decode_dict_words) {
            outfile << word << endl;
        }
        
        // Write phrases
        for (const auto& phrase : main_decode_dict_phrases) {
            for (size_t i = 0; i < phrase.size(); ++i) {
                if (i > 0) outfile << " ";
                outfile << phrase[i];
            }
            outfile << endl;
        }
        
        return outfile.good();
    }
    
    // Build local dictionary for rare words
    void build_local_dictionary(const vector<string>& rare_words) {
        local_decode_dict.clear();
        local_encode_dict.clear();
        
        for (const auto& word : rare_words) {
            local_decode_dict.push_back(word);
        }
        
        // Build encoding dictionary
        for (uint32_t i = 0; i < local_decode_dict.size(); ++i) {
            local_encode_dict[local_decode_dict[i]] = i;
        }
        
        // Calculate bits needed for local dictionary
        local_max_bit_length = 0;
        while ((1ULL << local_max_bit_length) < local_decode_dict.size()) {
            local_max_bit_length++;
        }
    }
    
    // Detect common phrases in the text
    void detect_phrases(const vector<string>& tokens) {
        PhraseFinder finder(min_phrase_freq, min_phrase_len, max_phrase_len);
        finder.find_phrases(tokens, main_encode_dict_words);
        
        auto frequent_phrases = finder.extract_frequent_phrases();
        phrase_frequencies.clear();
        
        for (const auto& phrase_pair : frequent_phrases) {
            phrase_frequencies.push_back(PhraseFreq(phrase_pair.first, phrase_pair.second));
        }
        
        // Sort by frequency in descending order
        sort(phrase_frequencies.begin(), phrase_frequencies.end(),
                 [](const PhraseFreq& a, const PhraseFreq& b) {
                     return a.frequency > b.frequency;
                 });
        
        // Print phrase statistics
        cout << "Found " << phrase_frequencies.size() << " common phrases:" << endl;
        for (size_t i = 0; i < min(phrase_frequencies.size(), size_t(20)); ++i) {
            cout << phrase_frequencies[i].to_string() << " (Frequency: " << phrase_frequencies[i].frequency << ")" << endl;
        }
        if (phrase_frequencies.size() > 20) {
            cout << "... and " << (phrase_frequencies.size() - 20) << " more phrases." << endl;
        }
    }
    
    // Finds phrases in the tokenized text and returns tokenized result with phrases
    vector<Token> tokenize_with_phrases(const vector<string>& word_tokens) {
        vector<Token> result;
        
        size_t i = 0;
        while (i < word_tokens.size()) {
            bool phrase_found = false;
            
            // Try to match phrases starting from longest to shortest
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
            
            if (!phrase_found) {
                result.push_back(Token(word_tokens[i]));
                i++;
            }
        }
        
        return result;
    }
    
public:
    TwoTierTextCompressor() = default;
    
    // Compression method
    bool compress(const string& dict_file, 
                  const string& input_file, 
                  const string& output_file) {
        // Step 1: Calculate word frequencies from input file
        ifstream infile(input_file);
        if (!infile) {
            cerr << "Error opening input file: " << input_file << endl;
            return false;
        }
        
        string text((istreambuf_iterator<char>(infile)), istreambuf_iterator<char>());
        infile.close();
        
        // Tokenize input text
        auto tokens = tokenize(text);
        
        // Calculate word frequencies
        word_frequencies.clear();
        for (const auto& token : tokens) {
            word_frequencies[token]++;
        }
        
        // Step 2: Load dictionary word list
        auto dict_words = load_dictionary_words(dict_file);
        if (dict_words.empty()) {
            cerr << "Failed to load dictionary words from: " << dict_file << endl;
            return false;
        }
        
        // Step 3: Build frequency-ordered main dictionary from dict_words
        vector<WordFreq> word_freq_list;
        for (const auto& word : dict_words) {
            // If word appears in input, use its actual frequency; otherwise use 1
            uint32_t freq = 1; // Default frequency
            auto it = word_frequencies.find(word);
            if (it != word_frequencies.end()) {
                freq = it->second;
            }
            word_freq_list.push_back(WordFreq(word, freq));
        }
        
        // Sort by frequency in descending order
        sort(word_freq_list.begin(), word_freq_list.end(), 
                  [](const WordFreq& a, const WordFreq& b) {
                      return a.frequency > b.frequency;
                  });
        
        // Build main dictionary for words
        main_decode_dict_words.clear();
        main_encode_dict_words.clear();
        
        for (const auto& wf : word_freq_list) {
            main_decode_dict_words.push_back(wf.word);
        }
        
        // Build encoding dictionary with code assignment (highest frequency -> smallest code)
        for (uint32_t i = 0; i < main_decode_dict_words.size(); ++i) {
            main_encode_dict_words[main_decode_dict_words[i]] = i;
        }
        
        // Step 4: Detect common phrases
        detect_phrases(tokens);
        
        // Build phrase dictionary
        main_decode_dict_phrases.clear();
        main_encode_dict_phrases.clear();
        
        for (const auto& pf : phrase_frequencies) {
            main_decode_dict_phrases.push_back(pf.words);
            string phrase_str = pf.to_string();
            main_encode_dict_phrases[phrase_str] = main_decode_dict_phrases.size() - 1;
        }
        
        // Calculate bits needed for main dictionary (words + phrases)
        main_max_bit_length = 0;
        size_t total_entries = main_decode_dict_words.size() + main_decode_dict_phrases.size();
        while ((1ULL << main_max_bit_length) < total_entries) {
            main_max_bit_length++;
        }
        
        // Step 5: Write main dictionary to eng.dict
        if (!write_main_dictionary("eng.dict")) {
            return false;
        }
        
        // Step 6: Identify words not in main dictionary
        vector<string> rare_words;
        
        for (const auto& token : tokens) {
            if (main_encode_dict_words.find(token) == main_encode_dict_words.end()) {
                if (find(rare_words.begin(), rare_words.end(), token) == rare_words.end()) {
                    rare_words.push_back(token);
                }
            }
        }
        
        // Step 7: Build local dictionary for rare words
        build_local_dictionary(rare_words);
        
        // Step 8: Tokenize the text with phrases
        auto phrase_tokens = tokenize_with_phrases(tokens);
        
        // Print dictionary statistics
        cout << "\n=== DICTIONARY STATISTICS ===" << endl;
        cout << "Main dictionary:" << endl;
        cout << "  Words: " << main_decode_dict_words.size() << endl;
        cout << "  Phrases: " << main_decode_dict_phrases.size() << endl;
        //cout << "  Wildcard patterns: " << main_decode_dict_wildcards.size() << endl;
        cout << "  Total main entries: " << (main_decode_dict_words.size() + main_decode_dict_phrases.size()) << endl;
        cout << "  Main dictionary bits per code: " << (int)main_max_bit_length << endl;

        cout << "Local dictionary:" << endl;
        cout << "  Rare words: " << local_decode_dict.size() << endl;
        cout << "  Local dictionary bits per code: " << (int)local_max_bit_length << endl;

        // Count actual usage
        size_t word_count = 0, phrase_count = 0, wildcard_count = 0;
        for (const auto& token : phrase_tokens) {
            switch (token.type) {
                case TokenType::WORD: word_count++; break;
                case TokenType::PHRASE: phrase_count++; break;
                //case TokenType::WILDCARD_PHRASE: wildcard_count++; break;
            }
        }

        cout << "\nToken usage:" << endl;
        cout << "  word tokens: " << word_count << endl;
        cout << "  phrase tokens: " << phrase_count << endl;
        //cout << "  wildcard tokens: " << wildcard_count << " (each uses 2 codes)" << endl;
        cout << "  total tokens: " << phrase_tokens.size() << endl;
        cout << "  effective codes written: " << (word_count + phrase_count) << endl;
        cout << "=============================\n" << endl;
        // Step 9: Compress the text
        BitWriter writer;
        
        // Write local dictionary
        writer.write_bits(local_decode_dict.size(), 32);
        writer.write_bits(local_max_bit_length, 8);
        
        // Write local dictionary words
        for (const auto& word : local_decode_dict) {
            // Write word length
            writer.write_bits(word.length(), 8);
            
            // Write word characters
            for (char c : word) {
                writer.write_bits(static_cast<uint8_t>(c), 8);
            }
        }
        
        // Write total token count
        writer.write_bits(phrase_tokens.size(), 32);
        
        // Compress tokens
        for (const auto& token : phrase_tokens) {
            bool is_phrase = (token.type == TokenType::PHRASE);
            bool is_main_dict = true;
            uint32_t code = 0;
            
            // Check token type
            if (is_phrase) {
                // For phrases, we look up in the phrase dictionary
                string phrase_str = token.to_string();
                auto phrase_it = main_encode_dict_phrases.find(phrase_str);
                if (phrase_it != main_encode_dict_phrases.end()) {
                    // Offset by the size of the word dictionary
                    code = main_decode_dict_words.size() + phrase_it->second;
                } else {
                    cerr << "Unexpected phrase: " << phrase_str << endl;
                    return false;
                }
            } else {
                // For words, first check main dictionary
                auto main_it = main_encode_dict_words.find(token.content);
                if (main_it != main_encode_dict_words.end()) {
                    code = main_it->second;
                } else {
                    // If not in main dict, use local dict
                    auto local_it = local_encode_dict.find(token.content);
                    if (local_it != local_encode_dict.end()) {
                        is_main_dict = false;
                        code = local_it->second;
                    } else {
                        // Unexpected: word should be in either dictionary
                        cerr << "Unexpected word: " << token.content << endl;
                        return false;
                    }
                }
            }
            
            // Write dictionary type flag (2 bits: 00=local word, 01=main word, 10=main phrase)
            if (!is_main_dict) {
                writer.write_bits(0, 2);  // Local dictionary word
                writer.write_bits(code, local_max_bit_length);
            } else if (!is_phrase) {
                writer.write_bits(1, 2);  // Main dictionary word
                writer.write_bits(code, main_max_bit_length);
            } else {
                writer.write_bits(2, 2);  // Main dictionary phrase
                writer.write_bits(code, main_max_bit_length);
            }
        }
        
        // Write to file
        return writer.write_to_file(output_file);
    }

// Decompression method
    bool decompress(const string& input_file, 
                    const string& dict_file,
                    const string& output_file) {
        // Load main dictionary
        if (!load_main_dictionary(dict_file)) {
            return false;
        }
        
        // Read compressed file
        ifstream infile(input_file, ios::binary);
        if (!infile) {
            cerr << "Error opening compressed file: " << input_file << endl;
            return false;
        }
        
        vector<uint8_t> buffer((istreambuf_iterator<char>(infile)), istreambuf_iterator<char>());
        infile.close();
        
        BitReader reader(buffer);
        
        // Read local dictionary
        uint32_t local_dict_size = reader.read_bits(32);
        uint8_t local_max_bits = reader.read_bits(8);
        
        local_decode_dict.clear();
        
        // Read local dictionary words
        for (uint32_t i = 0; i < local_dict_size; ++i) {
            // Read word length
            uint8_t word_length = reader.read_bits(8);
            
            // Read word characters
            string word;
            for (uint8_t j = 0; j < word_length; ++j) {
                char c = static_cast<char>(reader.read_bits(8));
                word += c;
            }
            
            local_decode_dict.push_back(word);
        }
        
        // Read total token count
        uint32_t token_count = reader.read_bits(32);
        
        // Decompress tokens
        ofstream outfile(output_file);
        if (!outfile) {
            cerr << "Error opening output file: " << output_file << endl;
            return false;
        }
        
        for (uint32_t i = 0; i < token_count; ++i) {
            // Read token type (2 bits)
            uint32_t token_type = reader.read_bits(2);
            
            // Read token code
            uint32_t code;
            
            switch (token_type) {
                case 0: // Local dictionary word
                    code = reader.read_bits(local_max_bits);
                    if (code < local_decode_dict.size()) {
                        outfile << local_decode_dict[code];
                    } else {
                        cerr << "Invalid local dictionary code: " << code << endl;
                        return false;
                    }
                    break;
                    
                case 1: // Main dictionary word
                    code = reader.read_bits(main_max_bit_length);
                    if (code < main_decode_dict_words.size()) {
                        outfile << main_decode_dict_words[code];
                    } else {
                        cerr << "Invalid main dictionary word code: " << code << endl;
                        return false;
                    }
                    break;
                    
                case 2: // Main dictionary phrase
                    code = reader.read_bits(main_max_bit_length);
                    if (code >= main_decode_dict_words.size()) {
                        // Adjust code to phrase dictionary index
                        uint32_t phrase_idx = code - main_decode_dict_words.size();
                        if (phrase_idx < main_decode_dict_phrases.size()) {
                            const auto& phrase = main_decode_dict_phrases[phrase_idx];
                            for (size_t j = 0; j < phrase.size(); ++j) {
                                if (j > 0) outfile << " ";
                                outfile << phrase[j];
                            }
                        } else {
                            cerr << "Invalid main dictionary phrase code: " << code << endl;
                            return false;
                        }
                    } else {
                        cerr << "Invalid phrase code (in word range): " << code << endl;
                        return false;
                    }
                    break;
                    
                default:
                    cerr << "Invalid token type: " << token_type << endl;
                    return false;
            }
        }
        
        return outfile.good();
    }
};

int main(int argc, char* argv[]) {
    if (argc < 5) {
        cout << "Usage: " << argv[0] << " <mode> <dict_file> <input_file> <output_file>" << endl;
        cout << "Modes: c or d" << endl;
        return 1;
    }
    
    string mode = argv[1];
    string dict_file = argv[2];
    string input_file = argv[3];
    string output_file = argv[4];
    
    TwoTierTextCompressor compressor;
    
    if (mode == "c") {
        if (compressor.compress(dict_file, input_file, output_file)) {
            cout << "Compression complete." << endl;
        } else {
            cerr << "Compression failed." << endl;
            return 1;
        }
    } else if (mode == "d") {
        if (compressor.decompress(input_file, dict_file, output_file)) {
            cout << "Decompression complete." << endl;
        } else {
            cerr << "Decompression failed." << endl;
            return 1;
        }
    } else {
        cerr << "Unknown mode: " << mode << endl;
        return 1;
    }
    
    return 0;
}
