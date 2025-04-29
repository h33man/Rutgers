#include <iostream>
#include <unordered_map>
#include <vector>
using namespace std;

struct word_info {
    uint32_t id;        // unique id of the word
    uint32_t freq;      // the number of times it has appeared in the training documents
    uint32_t num_books; // the number of different books it appears in
};

unordered_map<string, word_info> dict;

/*
1. load all words into the dict and build the mapping
2. Find the k most frequent words in the training set
3. The k smallest id numbers should be the top k words
4. Foreach book in the directory
5.   build phrase dictionary up to m uncommon words (currently m = 1), uncommon phrase mapped to 0

6. decide what the minimum threshhold is for retention of a phrase

7. read a sample book and apply the longest phrases in the dictionary to achieve the highest compression
   7b. Apply LZMA to the result
*/

/*
    load all words from all books in the directory
*/
void load_words(const string& dirname) {}) {
    for (const auto& book : books) {
        // Assuming each book is a string of words separated by spaces
        string word;
        for (char c : book) {
            if (c == ' ') {
                if (!word.empty()) {
                    unordered_map<string, 
                    dict[word]++;
                    word.clear();
                }
            } else {
                word += c;
            }
        }
        if (!word.empty()) {
            dict[word]++;
        }
    }
}

trie_dict phrases;

class trie_dict {
private:
    struct phrase_node {
        uint32_t id;
        uint32_t freq;
        // map words to node in the trie dict
        //            wordid     nodeid
        unordered_map<uint32_t, uint32_t> children;     
    };
    vector<phrase_node> nodes; // preallocate a huge chunk of nodes
    void add_node() {
        nodes.push_back(phrase_node());
        return nodes.size() - 1;
    }
public:
    trie_dict() {
        nodes.reserve(10000000); // reserve space for 1 million nodes
        add_node(); // root node
    }
    void add(const string& word) {
        uint32_t id = dict.lookup(word);
        if (id == 0) {
            //TODO: handle if word is not in the dictionary
        } else {
            // TODO: add the word to the trie
            //if 2nd uncommon word, end this sequence // at the end of the book there was an epilog. there were ...
        }
        //TODO: put it in the trie

    } 
};


void build_phrase(const char dirname[], uint32_t threshhold, ) {
    // for each word
    string w;
    word_info info = dict[w];
    phrases.add_word(info.id); // in the beginning, there were several...      300 1 5926 343 298  

    // in the               ==> 2
    // in the * there       ==> 1
    // in the * there were  ==> 1

    // at the end, there are a few things
    // in the end, there were a few things
    // at the ==> 1
    // in the end ==> 1
    // 
}