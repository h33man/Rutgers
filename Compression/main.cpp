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
#include <sstream>
#include <iomanip>

using namespace std;

// Trie structure for phrase detection and storage
class PhraseNode {
public:
    unordered_map<string, shared_ptr<PhraseNode>> children;
    bool is_end = false;
    uint32_t phrase_id = 0;
    uint32_t frequency = 0;
    vector<uint32_t> word_codes;
    
    // Check if this node contains a wildcard position
    bool has_wildcard = false;
    size_t wildcard_pos = 0;
    
    // For phrases with wildcards, store all encountered wildcards and their frequencies
    unordered_map<uint32_t, uint32_t> wildcard_codes;
};

class BitWriter {
private:
    vector<uint8_t> buffer;
    uint8_t current_byte = 0;
    uint8_t bits_used = 0;
    
public:
    void write_bits(uint32_t value, uint8_t bit_count) {
        while (bit_count > 0) {
            uint8_t bits_to_write = min(bit_count, static_cast<uint8_t>(8 - bits_used));
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
            uint8_t bits_to_read = min(bit_count, static_cast<uint8_t>(8 - bits_read));
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

struct PhraseInfo {
    vector<uint32_t> word_codes;
    uint32_t frequency = 0;
    bool has_wildcard = false;
    size_t wildcard_pos = 0;
    
    // For pretty printing
    string to_string(const vector<string>& word_dict) const {
        stringstream ss;
        for (size_t i = 0; i < word_codes.size(); ++i) {
            if (has_wildcard && i == wildcard_pos) {
                ss << "*";
            } else {
                ss << word_dict[word_codes[i]];
            }
            if (i < word_codes.size() - 1) ss << " ";
        }
        return ss.str();
    }
};

enum TokenType {
    WORD,       // Regular word
    PHRASE,     // Complete phrase
    WILDCARD    // Wildcard within a phrase
};

struct Token {
    TokenType type;
    string word;       // Single word or wildcard word
    uint32_t phrase_id;     // ID of the phrase (if type is PHRASE or WILDCARD)
    
    Token(TokenType t, const string& w, uint32_t id = 0)
        : type(t), word(w), phrase_id(id) {}
};

class TwoTierTextCompressor {
private:
    // Main dictionary
    unordered_map<string, uint32_t> main_encode_dict;
    vector<string> main_decode_dict;
    uint8_t main_max_bit_length = 0;
    
    // Local dictionary (for rare words)
    unordered_map<string, uint32_t> local_encode_dict;
    vector<string> local_decode_dict;
    uint8_t local_max_bit_length = 0;
    
    // Phrase dictionary 
    shared_ptr<PhraseNode> phrase_trie_root;
    vector<PhraseInfo> phrase_decode_dict;
    uint8_t phrase_max_bit_length = 0;
    
    // Statistics tracking
    uint32_t non_repeated_phrases = 0;
    
    // Frequency tracking
    unordered_map<string, uint32_t> word_frequencies;
    
    // Preprocessing and tokenization
    vector<string> tokenize_raw(const string& text) {
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
    
    // Build ngrams from token list
    vector<vector<string>> build_ngrams(const vector<string>& tokens, int min_size, int max_size) {
        vector<vector<string>> ngrams;
        
        for (size_t i = 0; i < tokens.size(); ++i) {
            for (int size = min_size; size <= max_size && i + size <= tokens.size(); ++size) {
                vector<string> ngram;
                for (int j = 0; j < size; ++j) {
                    ngram.push_back(tokens[i + j]);
                }
                ngrams.push_back(ngram);
            }
        }
        
        return ngrams;
    }
    
    // Find phrases with wildcards
    void find_wildcard_phrases(const vector<string>& tokens) {
        // Looking for patterns like "in the * of the" where * is any word
        unordered_map<string, unordered_map<size_t, unordered_map<string, uint32_t>>> wildcard_patterns;
        
        // Minimum frequency for phrase consideration
        const uint32_t MIN_PHRASE_FREQ = 2;
        
        // For each possible phrase length (2-5 words)
        for (int phrase_len = 2; phrase_len <= 5; ++phrase_len) {
            // For each possible starting position in tokens
            for (size_t start = 0; start + phrase_len <= tokens.size(); ++start) {
                // For each possible wildcard position within the phrase
                for (size_t wildcard_pos = 0; wildcard_pos < phrase_len; ++wildcard_pos) {
                    // Create pattern key by joining all words except wildcard
                    string pattern_key;
                    string wildcard_word = tokens[start + wildcard_pos];
                    
                    for (size_t i = 0; i < phrase_len; ++i) {
                        if (i == wildcard_pos) {
                            pattern_key += "*";
                        } else {
                            pattern_key += tokens[start + i];
                        }
                        
                        if (i < phrase_len - 1) {
                            pattern_key += " ";
                        }
                    }
                    
                    // Record this occurrence
                    wildcard_patterns[pattern_key][wildcard_pos][wildcard_word]++;
                }
            }
        }
        
        // Now analyze patterns to find frequently occurring ones
        for (const auto& pattern_entry : wildcard_patterns) {
            const string& pattern = pattern_entry.first;
            
            for (const auto& pos_entry : pattern_entry.second) {
                size_t wildcard_pos = pos_entry.first;
                uint32_t total_occurrences = 0;
                
                // Count total occurrences across all wildcard words
                for (const auto& word_entry : pos_entry.second) {
                    total_occurrences += word_entry.second;
                }
                
                // If pattern occurs frequently enough, add to phrase trie
                if (total_occurrences >= MIN_PHRASE_FREQ) {
                    // Parse pattern into words
                    vector<string> phrase_words;
                    stringstream ss(pattern);
                    string word;
                    
                    while (ss >> word) {
                        phrase_words.push_back(word);
                    }
                    
                    // Convert words to word codes
                    vector<uint32_t> word_codes;
                    for (size_t i = 0; i < phrase_words.size(); ++i) {
                        const string& next_word = phrase_words[i];
                        if (next_word != "*") {
                            // Get word code from main dictionary
                            auto it = main_encode_dict.find(next_word);
                            if (it != main_encode_dict.end()) {
                                word_codes.push_back(it->second);
                            } else {
                                // Add to main dictionary if not present
                                uint32_t new_code = main_decode_dict.size();
                                main_decode_dict.push_back(next_word);
                                main_encode_dict[next_word] = new_code;
                                word_codes.push_back(new_code);
                            }
                        } else {
                            // For wildcards, add a placeholder code (will be replaced during tokenization)
                            word_codes.push_back(UINT32_MAX); // Special value to indicate wildcard
                        }
                    }
                    
                    // Add the phrase pattern to trie
                    shared_ptr<PhraseNode> current = phrase_trie_root;
                    
                    for (size_t i = 0; i < phrase_words.size(); ++i) {
                        const string& next_word = phrase_words[i];
                        
                        if (next_word == "*") {
                            // Skip the wildcard in the trie traversal
                            continue;
                        }
                        
                        if (current->children.find(next_word) == current->children.end()) {
                            current->children[next_word] = make_shared<PhraseNode>();
                        }
                        
                        current = current->children[next_word];
                    }
                    
                    // Mark wildcard information
                    current->has_wildcard = true;
                    current->wildcard_pos = wildcard_pos;
                    current->is_end = true;
                    current->frequency = total_occurrences;
                    current->word_codes = word_codes;
                    
                    // Store all wildcard words encountered, using their codes
                    for (const auto& word_entry : pos_entry.second) {
                        const string& wildcard_word = word_entry.first;
                        uint32_t wildcard_code;
                        
                        auto it = main_encode_dict.find(wildcard_word);
                        if (it != main_encode_dict.end()) {
                            wildcard_code = it->second;
                        } else {
                            // Add to main dictionary if not present
                            wildcard_code = main_decode_dict.size();
                            main_decode_dict.push_back(wildcard_word);
                            main_encode_dict[wildcard_word] = wildcard_code;
                        }
                        
                        current->wildcard_codes[wildcard_code] = word_entry.second;
                    }
                    
                    // Add to phrase dictionary
                    PhraseInfo phrase_info;
                    phrase_info.word_codes = word_codes;
                    phrase_info.frequency = total_occurrences;
                    phrase_info.has_wildcard = true;
                    phrase_info.wildcard_pos = wildcard_pos;
                    
                    if (total_occurrences == 1) {
                        non_repeated_phrases++;
                    }
                    
                    phrase_decode_dict.push_back(phrase_info);
                    current->phrase_id = phrase_decode_dict.size() - 1;
                }
            }
        }
    }
    
    // Find and add regular phrases to trie
    void find_regular_phrases(const vector<string>& tokens) {
        // Count ngram frequencies
        unordered_map<string, uint32_t> ngram_freqs;
        
        // Minimum frequency for phrase consideration
        const uint32_t MIN_PHRASE_FREQ = 2;
        
        // Build ngrams and count frequencies
        auto ngrams = build_ngrams(tokens, 2, 5);  // 2-5 word phrases
        
        for (const auto& ngram : ngrams) {
            string ngram_str;
            for (size_t i = 0; i < ngram.size(); ++i) {
                ngram_str += ngram[i];
                if (i < ngram.size() - 1) ngram_str += " ";
            }
            ngram_freqs[ngram_str]++;
        }
        
        // Add frequent ngrams to phrase dictionary
        for (const auto& entry : ngram_freqs) {
            if (entry.second >= MIN_PHRASE_FREQ || (entry.second == 1 && ngram_freqs.size() < 1000)) {
                // Parse ngram string back to vector of words
                vector<string> phrase_words;
                stringstream ss(entry.first);
                string word;
                
                while (ss >> word) {
                    phrase_words.push_back(word);
                }
                
                // Convert words to word codes
                vector<uint32_t> word_codes;
                for (const string& word : phrase_words) {
                    // Get word code from main dictionary
                    auto it = main_encode_dict.find(word);
                    if (it != main_encode_dict.end()) {
                        word_codes.push_back(it->second);
                    } else {
                        // Add to main dictionary if not present
                        uint32_t new_code = main_decode_dict.size();
                        main_decode_dict.push_back(word);
                        main_encode_dict[word] = new_code;
                        word_codes.push_back(new_code);
                    }
                }
                
                // Add the phrase to trie
                shared_ptr<PhraseNode> current = phrase_trie_root;
                
                for (const string& next_word : phrase_words) {
                    if (current->children.find(next_word) == current->children.end()) {
                        current->children[next_word] = make_shared<PhraseNode>();
                    }
                    
                    current = current->children[next_word];
                }
                
                // Mark as end of phrase
                current->is_end = true;
                current->frequency = entry.second;
                current->word_codes = word_codes;
                
                // Add to phrase dictionary
                PhraseInfo phrase_info;
                phrase_info.word_codes = word_codes;
                phrase_info.frequency = entry.second;
                
                if (entry.second == 1) {
                    non_repeated_phrases++;
                }
                
                phrase_decode_dict.push_back(phrase_info);
                current->phrase_id = phrase_decode_dict.size() - 1;
            }
        }
    }
    
    // Process tokens with phrase recognition
    vector<Token> process_with_phrases(const vector<string>& raw_tokens) {
        vector<Token> processed_tokens;
        size_t i = 0;
        
        while (i < raw_tokens.size()) {
            // Try to match a phrase starting at position i
            shared_ptr<PhraseNode> current = phrase_trie_root;
            shared_ptr<PhraseNode> last_match = nullptr;
            size_t match_length = 0;
            size_t wildcard_pos = 0;
            string wildcard_word;
            
            for (size_t j = 0; j < 5 && i + j < raw_tokens.size(); ++j) {
                const string& token = raw_tokens[i + j];
                
                if (current->children.find(token) != current->children.end()) {
                    current = current->children[token];
                    
                    if (current->is_end) {
                        last_match = current;
                        match_length = j + 1;
                        
                        // Check for wildcard
                        if (current->has_wildcard && i + current->wildcard_pos < raw_tokens.size()) {
                            wildcard_pos = current->wildcard_pos;
                            wildcard_word = raw_tokens[i + wildcard_pos];
                        }
                    }
                } else {
                    break;
                }
            }
            
            // If we found a phrase match
            if (last_match != nullptr) {
                if (last_match->has_wildcard) {
                    // Add phrase token with separate wildcard token
                    processed_tokens.push_back(Token(PHRASE, "", last_match->phrase_id));
                    processed_tokens.push_back(Token(WILDCARD, wildcard_word, last_match->phrase_id));
                } else {
                    // Add regular phrase token
                    processed_tokens.push_back(Token(PHRASE, "", last_match->phrase_id));
                }
                
                i += match_length;
            } else {
                // No phrase match, add as regular word
                processed_tokens.push_back(Token(WORD, raw_tokens[i]));
                i++;
            }
        }
        
        return processed_tokens;
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
    
    // Load main dictionary and phrase dictionary for decompression
    bool load_dictionaries(const string& dict_file) {
        ifstream infile(dict_file);
        if (!infile) {
            cerr << "Error opening dictionary file: " << dict_file << endl;
            return false;
        }
        
        // Read dictionary header
        uint32_t word_count, phrase_count;
        infile >> word_count >> phrase_count;
        
        // Skip to next line
        string dummy;
        getline(infile, dummy);
        
        // Read words
        main_decode_dict.clear();
        main_encode_dict.clear();
        
        for (uint32_t i = 0; i < word_count; ++i) {
            string word;
            getline(infile, word);
            if (!word.empty()) {
                main_decode_dict.push_back(word);
            }
        }
        
        // Build encoding dictionary
        for (uint32_t i = 0; i < main_decode_dict.size(); ++i) {
            main_encode_dict[main_decode_dict[i]] = i;
        }
        
        // Calculate bits needed for main dictionary
        main_max_bit_length = 0;
        while ((1ULL << main_max_bit_length) < main_decode_dict.size()) {
            main_max_bit_length++;
        }
        
        // Read phrase dictionary
        phrase_decode_dict.clear();
        
        for (uint32_t i = 0; i < phrase_count; ++i) {
            string line;
            getline(infile, line);
            
            if (line.empty()) continue;
            
            stringstream ss(line);
            PhraseInfo phrase;
            
            // Read wildcard flag and position
            int has_wildcard;
            ss >> has_wildcard;
            phrase.has_wildcard = (has_wildcard == 1);
            
            if (phrase.has_wildcard) {
                ss >> phrase.wildcard_pos;
            }
            
            // Read word count and frequency
            uint32_t word_count;
            ss >> word_count >> phrase.frequency;
            
            // Read word codes
            for (uint32_t j = 0; j < word_count; ++j) {
                uint32_t code;
                ss >> code;
                phrase.word_codes.push_back(code);
            }
            
            phrase_decode_dict.push_back(phrase);
        }
        
        // Calculate bits needed for phrase dictionary
        phrase_max_bit_length = 0;
        while ((1ULL << phrase_max_bit_length) < phrase_decode_dict.size()) {
            phrase_max_bit_length++;
        }
        
        return true;
    }
    
    // Write main dictionary and phrase dictionary to a file
    bool write_dictionaries(const string& dict_file) {
        ofstream outfile(dict_file);
        if (!outfile) {
            cerr << "Error opening dictionary file for writing: " << dict_file << endl;
            return false;
        }
        
        // Write dictionary header: word count and phrase count
        outfile << main_decode_dict.size() << " " << phrase_decode_dict.size() << endl;
        
        // Write words
        for (const auto& word : main_decode_dict) {
            outfile << word << endl;
        }
        
        // Write phrases
        for (const auto& phrase : phrase_decode_dict) {
            // Write wildcard flag and position
            outfile << (phrase.has_wildcard ? 1 : 0) << " ";
            
            if (phrase.has_wildcard) {
                outfile << phrase.wildcard_pos << " ";
            }
            
            // Write word count and frequency
            outfile << phrase.word_codes.size() << " " << phrase.frequency << " ";
            
            // Write word codes
            for (uint32_t code : phrase.word_codes) {
                outfile << code << " ";
            }
            
            outfile << endl;
        }
        
        return true;
    }
    
    // Build local dictionary for rare words
    void build_local_dictionary(const vector<string>& rare_words) {
        local_decode_dict.clear();
        local_encode_dict.clear();
        
        for (const auto& word : rare_words) {
            if (find(local_decode_dict.begin(), local_decode_dict.end(), word) == local_decode_dict.end()) {
                local_decode_dict.push_back(word);
            }
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
public:
    TwoTierTextCompressor() {
        // Initialize phrase trie root
        phrase_trie_root = make_shared<PhraseNode>();
        non_repeated_phrases = 0;
    }
    
    // Print statistics about phrases
    void print_phrase_stats() const {
        cout << "\nPhrase Statistics:" << endl;
        cout << "-----------------" << endl;
        cout << "Total phrases found: " << phrase_decode_dict.size() << endl;
        cout << "Non-repeated phrases: " << non_repeated_phrases << endl;
        
        uint32_t wildcard_phrases = 0;
        uint32_t regular_phrases = 0;
        
        for (const auto& phrase : phrase_decode_dict) {
            if (phrase.has_wildcard) {
                wildcard_phrases++;
            } else {
                regular_phrases++;
            }
        }
        
        cout << "Regular phrases: " << regular_phrases << endl;
        cout << "Wildcard phrases: " << wildcard_phrases << endl;
        
        // Print top phrases by frequency
        cout << "\nTop 10 phrases by frequency:" << endl;
        vector<pair<uint32_t, size_t>> sorted_phrases;
        for (size_t i = 0; i < phrase_decode_dict.size(); ++i) {
            sorted_phrases.push_back({phrase_decode_dict[i].frequency, i});
        }
        
        sort(sorted_phrases.begin(), sorted_phrases.end(), 
                 [](const auto& a, const auto& b) { return a.first > b.first; });
        
        size_t count = min(size_t(10), sorted_phrases.size());
        for (size_t i = 0; i < count; ++i) {
            const auto& phrase = phrase_decode_dict[sorted_phrases[i].second];
            cout << setw(5) << phrase.frequency << " | " 
                      << phrase.to_string(main_decode_dict) << endl;
        }
    }
    
    // Compression method
    bool compress(const string& dict_file, 
                  const string& input_file, 
                  const string& output_file) {
        // Reset phrase structures
        phrase_trie_root = make_shared<PhraseNode>();
        phrase_decode_dict.clear();
        non_repeated_phrases = 0;
        
        // Step 1: Read input file
        ifstream infile(input_file);
        if (!infile) {
            cerr << "Error opening input file: " << input_file << endl;
            return false;
        }
        
        string text((istreambuf_iterator<char>(infile)), istreambuf_iterator<char>());
        infile.close();
        
        // Step 2: Tokenize input text
        auto raw_tokens = tokenize_raw(text);
        
        // Step 3: Calculate word frequencies
        word_frequencies.clear();
        for (const auto& token : raw_tokens) {
            word_frequencies[token]++;
        }
        
        // Step 4: Load dictionary word list
        auto dict_words = load_dictionary_words(dict_file);
        if (dict_words.empty()) {
            cerr << "Failed to load dictionary words from: " << dict_file << endl;
            return false;
        }
        
        // Step 5: Build frequency-ordered main dictionary from dict_words
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
        
        // Build main dictionary
        main_decode_dict.clear();
        main_encode_dict.clear();
        
        for (const auto& wf : word_freq_list) {
            main_decode_dict.push_back(wf.word);
        }
        
        // Build encoding dictionary with code assignment (highest frequency -> smallest code)
        for (uint32_t i = 0; i < main_decode_dict.size(); ++i) {
            main_encode_dict[main_decode_dict[i]] = i;
        }
        
        // Calculate bits needed for main dictionary
        main_max_bit_length = 0;

        while ((1ULL << main_max_bit_length) < main_decode_dict.size()) {
            main_max_bit_length++;
        }
        
        // Step 6: Find phrases with wildcards
        find_wildcard_phrases(raw_tokens);
        
        // Step 7: Find regular phrases
        find_regular_phrases(raw_tokens);
        
        // Print phrase statistics
        print_phrase_stats();
        
        // Step 8: Process tokens with phrase recognition
        auto processed_tokens = process_with_phrases(raw_tokens);
        
        // Step 9: Collect rare words (words not in the main dictionary)
        vector<string> rare_words;
        for (const auto& token : processed_tokens) {
            if (token.type == WORD && main_encode_dict.find(token.word) == main_encode_dict.end()) {
                rare_words.push_back(token.word);
            }
        }
        
        // Step 10: Build local dictionary for rare words
        build_local_dictionary(rare_words);
        
        // Step 11: Write dictionaries to file
        if (!write_dictionaries("eng.dict")) {
            cerr << "Failed to write dictionaries to file: eng.dict" << endl;
            return false;
        }
        
        // Step 12: Write compressed data
        BitWriter writer;
        
        // Write local dictionary size
        writer.write_bits(local_decode_dict.size(), 16);
        
        // Write local dictionary
        for (const auto& word : local_decode_dict) {
            writer.write_bits(word.size(), 8);  // Word length (up to 255 chars)
            for (char c : word) {
                writer.write_bits(static_cast<uint8_t>(c), 8);
            }
        }
        
        // Process tokens and write compressed data
        for (size_t i = 0; i < processed_tokens.size(); ++i) {
            const auto& token = processed_tokens[i];
            
            if (token.type == WORD) {
                // Check if word is in main dictionary
                auto it = main_encode_dict.find(token.word);
                if (it != main_encode_dict.end()) {
                    // Word in main dictionary
                    writer.write_bits(0, 1);  // Type bit: 0 = main dictionary word
                    writer.write_bits(it->second, main_max_bit_length);
                } else {
                    // Word in local dictionary
                    auto local_it = local_encode_dict.find(token.word);
                    if (local_it != local_encode_dict.end()) {
                        writer.write_bits(1, 1);  // Type bit: 1 = local dictionary word
                        writer.write_bits(local_it->second, local_max_bit_length);
                    } else {
                        cerr << "Error: Word not found in either dictionary: " << token.word << endl;
                        return false;
                    }
                }
            } else if (token.type == PHRASE) {
                // Phrase reference
                writer.write_bits(2, 2);  // Type bits: 10 = phrase reference
                writer.write_bits(token.phrase_id, phrase_max_bit_length);
            } else if (token.type == WILDCARD) {
                // Wildcard word in phrase
                writer.write_bits(3, 2);  // Type bits: 11 = wildcard word
                
                // Check if wildcard word is in main dictionary
                auto it = main_encode_dict.find(token.word);
                if (it != main_encode_dict.end()) {
                    // Word in main dictionary
                    writer.write_bits(0, 1);  // Word type bit: 0 = main dictionary word
                    writer.write_bits(it->second, main_max_bit_length);
                } else {
                    // Word in local dictionary
                    auto local_it = local_encode_dict.find(token.word);
                    if (local_it != local_encode_dict.end()) {
                        writer.write_bits(1, 1);  // Word type bit: 1 = local dictionary word
                        writer.write_bits(local_it->second, local_max_bit_length);
                    } else {
                        cerr << "Error: Wildcard word not found in either dictionary: " << token.word << endl;
                        return false;
                    }
                }
            }
        }
        
        // Write compressed data to file
        if (!writer.write_to_file(output_file)) {
            cerr << "Error writing compressed data to file: " << output_file << endl;
            return false;
        }
        
        return true;
    }

    bool decompress(const string& dict_file, 
                    const string& input_file, 
                    const string& output_file) {
        // Step 1: Load dictionaries
        if (!load_dictionaries(dict_file)) {
            cerr << "Failed to load dictionaries from file: " << dict_file << endl;
            return false;
        }
        
        // Step 2: Read compressed data
        ifstream infile(input_file, ios::binary);
        if (!infile) {
            cerr << "Error opening compressed file: " << input_file << endl;
            return false;
        }
        
        // Read file into buffer
        vector<uint8_t> buffer((istreambuf_iterator<char>(infile)), istreambuf_iterator<char>());
        infile.close();
        
        BitReader reader(buffer);
        
        // Step 3: Read local dictionary
        uint32_t local_dict_size = reader.read_bits(16);
        
        vector<string> local_decode_dict;
        for (uint32_t i = 0; i < local_dict_size; ++i) {
            uint8_t word_len = reader.read_bits(8);
            string word;
            for (uint8_t j = 0; j < word_len; ++j) {
                char c = static_cast<char>(reader.read_bits(8));
                word += c;
            }
            local_decode_dict.push_back(word);
        }
        
        // Calculate bits needed for local dictionary
        uint8_t local_max_bit_length = 0;
        while ((1ULL << local_max_bit_length) < local_decode_dict.size()) {
            local_max_bit_length++;
        }
        
        // Step 4: Decompress data and write to output file
        ofstream outfile(output_file);
        if (!outfile) {
            cerr << "Error opening output file: " << output_file << endl;
            return false;
        }
        
        while (reader.has_more()) {
            // Read token type
            uint8_t type_bits = reader.read_bits(1);
            
            if (type_bits == 0) {
                // Main dictionary word
                uint32_t word_code = reader.read_bits(main_max_bit_length);
                if (word_code < main_decode_dict.size()) {
                    outfile << main_decode_dict[word_code];
                } else {
                    cerr << "Invalid word code in main dictionary: " << word_code << endl;
                    return false;
                }
            } else {
                // Additional type bit needed
                uint8_t additional_type_bit = reader.read_bits(1);
                
                if (additional_type_bit == 0) {
                    // Local dictionary word
                    uint32_t word_code = reader.read_bits(local_max_bit_length);
                    if (word_code < local_decode_dict.size()) {
                        outfile << local_decode_dict[word_code];
                    } else {
                        cerr << "Invalid word code in local dictionary: " << word_code << endl;
                        return false;
                    }
                } else if (additional_type_bit == 1) {
                    // Phrase reference
                    uint32_t phrase_id = reader.read_bits(phrase_max_bit_length);
                    if (phrase_id < phrase_decode_dict.size()) {
                        const auto& phrase = phrase_decode_dict[phrase_id];
                        
                        // Handle phrases differently based on whether they have a wildcard
                        if (phrase.has_wildcard) {
                            // For phrases with wildcards, we need the next token to be the wildcard word
                            if (!reader.has_more()) {
                                cerr << "Error: Expected wildcard word after wildcard phrase" << endl;
                                return false;
                            }
                            
                            // Read wildcard word type
                            uint8_t wildcard_type = reader.read_bits(2);
                            if (wildcard_type != 3) {
                                cerr << "Error: Expected wildcard token after wildcard phrase" << endl;
                                return false;
                            }
                            
                            // Read wildcard word
                            uint8_t word_dict_type = reader.read_bits(1);
                            uint32_t word_code;
                            string wildcard_word;
                            
                            if (word_dict_type == 0) {
                                // Main dictionary word
                                word_code = reader.read_bits(main_max_bit_length);
                                if (word_code < main_decode_dict.size()) {
                                    cout << "word: " << main_decode_dict[word_code] << endl;
                                    wildcard_word = main_decode_dict[word_code];
                                } else {
                                    cerr << "Invalid wildcard word code in main dictionary: " << word_code << endl;
                                    return false;
                                }
                            } else {
                                // Local dictionary word
                                word_code = reader.read_bits(local_max_bit_length);
                                if (word_code < local_decode_dict.size()) {
                                    wildcard_word = local_decode_dict[word_code];
                                } else {
                                    cerr << "Invalid wildcard word code in local dictionary: " << word_code << endl;
                                    return false;
                                }
                            }
                            
                            // Output phrase with wildcard word inserted
                            for (size_t i = 0; i < phrase.word_codes.size(); ++i) {
                                if (i > 0) outfile << " ";
                                
                                if (i == phrase.wildcard_pos) {
                                    outfile << wildcard_word;
                                } else {
                                    uint32_t code = phrase.word_codes[i];
                                    if (code < main_decode_dict.size()) {
                                        outfile << main_decode_dict[code];
                                        cout << "word: " << main_decode_dict[code] << endl;
                                    } else {
                                        cerr << "Invalid word code in phrase: " << code << endl;
                                        return false;
                                    }
                                }
                            }
                        } else {
                            // Regular phrase
                            for (size_t i = 0; i < phrase.word_codes.size(); ++i) {
                                if (i > 0) outfile << " ";
                                
                                uint32_t code = phrase.word_codes[i];
                                if (code < main_decode_dict.size()) {
                                    outfile << main_decode_dict[code];
                                } else {
                                    cerr << "Invalid word code in phrase: " << code << endl;
                                    return false;
                                }
                            }
                        }
                    } else {
                        cerr << "Invalid phrase ID: " << phrase_id << endl;
                        return false;
                    }
                }
            }
            
            // Add space after each token (except certain punctuation)
            if (reader.has_more()) {
                outfile << " ";
            }
        }
        
        return true;
    }
};

// Main function
int main(int argc, char* argv[]) {
    if (argc < 4) {
        cout << "Usage for compression: " << argv[0] << " c dictionary_file input_file output_file" << endl;
        cout << "Usage for decompression: " << argv[0] << " d dictionary_file input_file output_file" << endl;
        return 1;
    }
    
    string mode = argv[1];
    string dict_file = argv[2];
    string input_file = argv[3];
    string output_file = argv[4];
    
    TwoTierTextCompressor compressor;
    bool success = false;
    
    if (mode == "c") {
        cout << "Compressing " << input_file << " to " << output_file << " using dictionary " << dict_file << endl;
        success = compressor.compress(dict_file, input_file, output_file);
    } else if (mode == "d") {
        cout << "Decompressing " << input_file << " to " << output_file << " using dictionary " << dict_file << endl;
        success = compressor.decompress(dict_file, input_file, output_file);
    } else {
        cerr << "Invalid mode. Use 'c' for compression or 'd' for decompression." << endl;
        return 1;
    }
    
    if (success) {
        cout << "Operation completed successfully." << endl;
    } else {
        cerr << "Operation failed." << endl;
        return 1;
    }
    
    return 0;
}
