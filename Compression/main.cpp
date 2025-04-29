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
#include <experimental/filesystem>

class BitWriter {
private:
    std::vector<uint8_t> buffer;
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
    
    const std::vector<uint8_t>& get_buffer() const {
        return buffer;
    }
    
    bool write_to_file(const std::string& filename) {
        flush();
        std::ofstream outfile(filename, std::ios::binary);
        if (!outfile) return false;
        outfile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        return outfile.good();
    }
};

class BitReader {
private:
    const std::vector<uint8_t>& buffer;
    size_t current_byte_idx = 0;
    uint8_t bits_read = 0;
    
public:
    BitReader(const std::vector<uint8_t>& buf) : buffer(buf) {}
    
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
    std::string word;
    uint32_t frequency;
    
    WordFreq(const std::string& w, uint32_t f) : word(w), frequency(f) {}
    
    bool operator<(const WordFreq& other) const {
        return frequency < other.frequency;
    }
};

class TwoTierTextCompressor {
private:
    // Main dictionary
    std::unordered_map<std::string, uint32_t> main_encode_dict;
    std::vector<std::string> main_decode_dict;
    uint8_t main_max_bit_length = 0;
    
    // Local dictionary (for rare words)
    std::unordered_map<std::string, uint32_t> local_encode_dict;
    std::vector<std::string> local_decode_dict;
    uint8_t local_max_bit_length = 0;
    
    // Frequency tracking
    std::unordered_map<std::string, uint32_t> word_frequencies;
    
    // Preprocessing and tokenization
    std::vector<std::string> tokenize(const std::string& text) {
        std::vector<std::string> tokens;
        std::string current_token;
        
        for (char c : text) {
            if (std::isalnum(c) || c == '\'') {
                current_token += std::tolower(c);
            } else {
                if (!current_token.empty()) {
                    tokens.push_back(current_token);
                    current_token.clear();
                }
                if (!std::isspace(c)) {
                    tokens.push_back(std::string(1, c));
                }
            }
        }
        
        if (!current_token.empty()) {
            tokens.push_back(current_token);
        }
        
        return tokens;
    }
    
    // Load dictionary words from file (just the list of words)
    std::vector<std::string> load_dictionary_words(const std::string& dict_file) {
        std::ifstream infile(dict_file);
        if (!infile) {
            std::cerr << "Error opening dictionary file: " << dict_file << std::endl;
            return {};
        }
        
        std::vector<std::string> dict_words;
        std::string word;
        
        while (std::getline(infile, word)) {
            if (!word.empty()) {
                // Convert to lowercase for consistency
                std::transform(word.begin(), word.end(), word.begin(), ::tolower);
                dict_words.push_back(word);
            }
        }
        
        return dict_words;
    }
    
    // Load main dictionary for decompression
    bool load_main_dictionary(const std::string& dict_file) {
        std::ifstream infile(dict_file);
        if (!infile) {
            std::cerr << "Error opening dictionary file: " << dict_file << std::endl;
            return false;
        }
        
        std::string word;
        main_decode_dict.clear();
        main_encode_dict.clear();
        
        while (std::getline(infile, word)) {
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
        
        return true;
    }
    
    // Write main dictionary to a file
    bool write_main_dictionary(const std::string& dict_file) {
        std::ofstream outfile(dict_file);
        if (!outfile) {
            std::cerr << "Error opening dictionary file for writing: " << dict_file << std::endl;
            return false;
        }
        
        for (const auto& word : main_decode_dict) {
            outfile << word << std::endl;
        }
        
        return true;
    }
    
    // Build local dictionary for rare words
    void build_local_dictionary(const std::vector<std::string>& rare_words) {
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
    
public:
    TwoTierTextCompressor() = default;
    
    // Compression method
    bool compress(const std::string& dict_file, 
                  const std::string& input_file, 
                  const std::string& output_file) {
        // Step 1: Calculate word frequencies from input file
        std::ifstream infile(input_file);
        if (!infile) {
            std::cerr << "Error opening input file: " << input_file << std::endl;
            return false;
        }
        
        std::string text((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
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
            std::cerr << "Failed to load dictionary words from: " << dict_file << std::endl;
            return false;
        }
        
        // Step 3: Build frequency-ordered main dictionary from dict_words
        std::vector<WordFreq> word_freq_list;
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
        std::sort(word_freq_list.begin(), word_freq_list.end(), 
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
        
        // Step 4: Write main dictionary to eng.dict
        if (!write_main_dictionary("eng.dict")) {
            return false;
        }
        
        // Step 5: Identify words not in main dictionary
        std::vector<std::string> rare_words;
        std::vector<std::string> compressed_tokens;
        
        for (const auto& token : tokens) {
            if (main_encode_dict.find(token) == main_encode_dict.end()) {
                if (std::find(rare_words.begin(), rare_words.end(), token) == rare_words.end()) {
                    rare_words.push_back(token);
                }
            }
            compressed_tokens.push_back(token);
        }
        
        // Step 6: Build local dictionary for rare words
        build_local_dictionary(rare_words);
        
        // Step 7: Compress the text
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
        writer.write_bits(compressed_tokens.size(), 32);
        
        // Compress tokens
        for (const auto& token : compressed_tokens) {
            bool is_main_dict = true;
            uint32_t code = 0;
            
            // Check main dictionary first
            auto main_it = main_encode_dict.find(token);
            if (main_it != main_encode_dict.end()) {
                code = main_it->second;
            } else {
                // If not in main dict, use local dict
                auto local_it = local_encode_dict.find(token);
                if (local_it != local_encode_dict.end()) {
                    is_main_dict = false;
                    code = local_it->second;
                } else {
                    // Unexpected: word should be in either dictionary
                    std::cerr << "Unexpected word: " << token << std::endl;
                    return false;
                }
            }
            
            // Write dictionary flag and code
            writer.write_bits(is_main_dict ? 1 : 0, 1);
            writer.write_bits(code, is_main_dict ? main_max_bit_length : local_max_bit_length);
        }
        
        // Write to file
        return writer.write_to_file(output_file);
    }
    
    // Decompression method
    bool decompress(const std::string& input_file, 
                    const std::string& dict_file,
                    const std::string& output_file) {
        // Load main dictionary
        if (!load_main_dictionary(dict_file)) {
            return false;
        }
        
        // Read compressed file
        std::ifstream infile(input_file, std::ios::binary);
        if (!infile) {
            std::cerr << "Error opening compressed file: " << input_file << std::endl;
            return false;
        }
        
        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
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
            std::string word;
            for (uint8_t j = 0; j < word_length; ++j) {
                char c = static_cast<char>(reader.read_bits(8));
                word += c;
            }
            
            local_decode_dict.push_back(word);
        }
        
        // Read total token count
        uint32_t token_count = reader.read_bits(32);
        
        // Decompress tokens
        std::ofstream outfile(output_file);
        if (!outfile) {
            std::cerr << "Error opening output file: " << output_file << std::endl;
            return false;
        }
        
        for (uint32_t i = 0; i < token_count; ++i) {
            // Read dictionary flag
            bool is_main_dict = reader.read_bits(1) == 1;
            
            // Read code
            uint32_t code = reader.read_bits(is_main_dict ? main_max_bit_length : local_max_bits);
            
            // Decode word
            std::string word;
            if (is_main_dict) {
                if (code < main_decode_dict.size()) {
                    word = main_decode_dict[code];
                } else {
                    std::cerr << "Invalid main dictionary code: " << code << std::endl;
                    return false;
                }
            } else {
                if (code < local_decode_dict.size()) {
                    word = local_decode_dict[code];
                } else {
                    std::cerr << "Invalid local dictionary code: " << code << std::endl;
                    return false;
                }
            }
            
            outfile << word;
        }
        
        return outfile.good();
    }
};

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cout << "Usage: " << argv[0] << " <mode> <dict_file> <input_file> <output_file>" << std::endl;
        std::cout << "Modes: compress or decompress" << std::endl;
        return 1;
    }
    
    std::string mode = argv[1];
    std::string dict_file = argv[2];
    std::string input_file = argv[3];
    std::string output_file = argv[4];
    
    TwoTierTextCompressor compressor;
    
    if (mode == "compress") {
        if (compressor.compress(dict_file, input_file, output_file)) {
            std::cout << "Compression complete." << std::endl;
        } else {
            std::cerr << "Compression failed." << std::endl;
            return 1;
        }
    } else if (mode == "decompress") {
        if (compressor.decompress(input_file, dict_file, output_file)) {
            std::cout << "Decompression complete." << std::endl;
        } else {
            std::cerr << "Decompression failed." << std::endl;
            return 1;
        }
    } else {
        std::cerr << "Unknown mode: " << mode << std::endl;
        return 1;
    }
    
    return 0;
}
