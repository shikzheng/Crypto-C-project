// Name: decrypt.cpp
// Purpose: Decrypt a substitution cipher

#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include <map>
#include <stack>
#include <algorithm>
#include <cctype>
#include <regex>

using namespace std;

const string DICTIONARY = "english_words-1.txt";
const string PLAINTEXT = "plaintext_dictionary.txt";

enum alphabet {a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z};


//storing cipher text in an easy to use container;
vector<vector<string>> cipher;

//number of keys allowed per letter; we must maintain all these values to be >= 0 for the decryption to be correct
int freq[26];

//number of occurences of a key; will use these to weigh words
int occurences[103] = {0};

//vector to hold the dictionary words, grouped by word lengths for easier lookup
vector<vector<string>> dict;

//vector to hold plaintexts
vector<string> plaintexts;

//vector to hold the character counts of known plaintexts
vector<vector<int>> plaintext_count;

//mappings from character counts to known plaintexts
multimap<int, int> count_to_plaintext;

//maintain a stack to remember deciphers from key -> char
stack<pair<string, char>> ops;

//maintain a stack to remember number of decipher of key -> char per word
stack<int> attempts;

//maintain a stack to remember position of deciphers from key -> char
stack<pair<int, int>> pos;

//maintain a stack to remember number of positions which tried key -> char
stack<int> numpos;

void clear_stacks()
{
    while (!ops.empty())
	ops.pop();
    
    while (!attempts.empty())
	attempts.pop();

    while (!pos.empty())
	pos.pop();

    while (!numpos.empty())
	numpos.pop();
}

//number of keys allowed per letter
void set_freq()
{
    freq[a] = 8;
    freq[b] = 1;
    freq[c] = 3;
    freq[d] = 4;
    freq[e] = 13;
    freq[f] = 2;
    freq[g] = 2;
    freq[h] = 6;
    freq[i] = 7;
    freq[j] = 1;
    freq[k] = 1;
    freq[l] = 4;
    freq[m] = 2;
    freq[n] = 7;
    freq[o] = 8;
    freq[p] = 2;
    freq[q] = 1;
    freq[r] = 6;
    freq[s] = 6;
    freq[t] = 9;
    freq[u] = 3;
    freq[v] = 1;
    freq[w] = 2;
    freq[x] = 1;
    freq[y] = 2;
    freq[z] = 1;
}

//count characters in each word
vector<int> count_characters(const string& s)
{
    vector<int> chars;

    stringstream line(s);
    string word;
    while (line >> word)
	chars.push_back(word.size());

    return chars;	
}

//storing words from plaintext file
bool load_plaintexts()
{
    //reduce copying
    plaintexts.reserve(10);
    
    //open plaintext file
    ifstream file(PLAINTEXT);

    if (!file.is_open())
    {
	cerr << "error: cannot open " << PLAINTEXT << "\n";
	return false;
    }

    string line;
    while (getline(file, line))
    {
	if (line.size() > 1)	//ignore empty lines
	{
	    //count the characters in each word
	    vector<int> chars = count_characters(line);
	    
	    //create mappings from character count to known plaintexts
	    bool mapped = false;
	    for (int i = 0; i < plaintext_count.size(); ++i)
	    {
		if (plaintext_count[i] == chars)
		{
		    count_to_plaintext.insert(pair<int, int>(i, plaintexts.size()));
		    mapped = true;
		}
	    }
	    
	    if (!mapped)
		count_to_plaintext.insert(pair<int, int>(plaintext_count.size(), plaintexts.size()));

	    
	    plaintext_count.push_back(chars);
	    plaintexts.push_back(line);
	}
    }
    
    file.close();
    return true;
}

//storing words from dictionary
bool load_dictionary()
{
    dict.resize(28); //longest dictionary word is 28

    // number of words per length to reduce copying
    dict[0].reserve(1);
    dict[1].reserve(140);
    dict[2].reserve(852);
    dict[3].reserve(3130);
    dict[4].reserve(6914);
    dict[5].reserve(11492);
    dict[6].reserve(16877);
    dict[7].reserve(19458);
    dict[8].reserve(16692);
    dict[9].reserve(11880);
    dict[10].reserve(8373);
    dict[11].reserve(5811);
    dict[12].reserve(3676);
    dict[13].reserve(2101);
    dict[14].reserve(1159);
    dict[15].reserve(583);
    dict[16].reserve(229);
    dict[17].reserve(107);
    dict[18].reserve(39);
    dict[19].reserve(29);
    dict[20].reserve(11);
    dict[21].reserve(4);
    dict[22].reserve(2);
    //dict[23].reserve(0);
    dict[24].reserve(1);
    //dict[25].reserve(0);
    //dict[26].reserve(0);
    dict[27].reserve(1);

    //open file
    ifstream file(DICTIONARY);
    
    if(!file.is_open())
    {
	cerr << "error: cannot open file: " << DICTIONARY << "\n";
	return false;
    }

    //reading and storing
    string word;
    while (file >> word)
    {
	
	while (dict.size() < word.length())
	    dict.push_back(vector<string>());

	dict[word.length()-1].push_back(word);
    }

    file.close();
    return true;
}

// stores ciphertext into global vector
// counts occurences of keys
// returns a vector containing the characters per word
vector<int> get_characters(const string& ciphertext)
{
    //vector to store counts
    vector<int> chars;

    //tokenize the ciphertext
    stringstream line(ciphertext);
    
    int idx = 0;

    string word;
    while (line >> word)
    {
	int count = 0;

	//adding word to cipher 
	cipher.push_back(vector<string>());

	//tokenize each word
	stringstream tokens(word);

	int i;
	while (tokens >> i)
	{
	    //increase character count
	    ++count;

	    //increase key count
	    ++(occurences[i]);

	    //add key to cipher
	    cipher[idx].push_back(to_string(i));

	    //ignore ','
	    if (tokens.peek() == ',')
		tokens.ignore();
	}

	chars.push_back(count);
	
	++idx;
    }

    return chars;
}

//check if a word is fully deciphered
bool is_plain(const vector<string>& word)
{
    for (const string& s : word)
	if (!islower(s[0]))
	    return false;
    return true;
}

//check if the cipher is fully deciphered
bool check_cipher(const vector<vector<string>>& cipher)
{
    //start from end because decryption happens from the beginning
    for (auto rit = cipher.rbegin(); rit != cipher.rend(); ++rit)
	if (!is_plain(*rit))
	    return false;
    return true;
}

//make a regular expression from a word from ciphertext
string make_regex(const vector<string>& word, bool last = false)
{
    //starts with
    string rgx = "^";
    
    //including characters to reduce matches
    for (const string& letter : word)
	if (islower(letter[0]))
	    rgx += letter[0];
	else
	    rgx += '.';

    //special case for last word in cipher (it can be truncated)
    if (last)
	rgx += ".*";

    //ends
    rgx += '$';

    return rgx;
}

//check if a partially deciphered word is in dictionary
bool in_dict(vector<string>& word, bool last = false)
{
    //make regular expression
    string rg = make_regex(word, last);
    regex r(rg);

    //special case for last word in cipher (it can be truncated)
    if (last)
    {
	//check dictionary for all words >= length of last word
	for (int i = word.size()-1; i < dict.size(); ++i)
	    for (auto& s : dict[i])
		if (regex_match(s, r))
		    return true;
	return false;
    }
    
    //check all words of the same length
    for (auto& s : dict[word.size()-1])
	if (regex_match(s, r))
	    return true;
    return false;
}

//attempt to decrypt key -> c
bool try_letter(const string key, char c, bool plain = false, vector<vector<string>>& cipher = ::cipher)
{
    numpos.push(int(0));

    //key count doesn't hold
    if(freq[c-97] == 0)
        return false;

    --(freq[c-97]);
    
    //replace all occurences of key with char
    for (int i = 0; i < cipher.size(); ++i)
    {
    	for (int j = 0; j < cipher[i].size(); ++j)
	{
	    if (cipher[i][j] == key)
	    {
		//keep track of number replacements
		numpos.top() += 1;

		cipher[i][j] = c;
		
		//keep track of location of replacement
		pos.push(pair<int, int>(i, j));
		
		if(!plain)
		{
		    //check if the paritally decrypted word is in dictionary
		    if (!in_dict(cipher[i], bool(i == (cipher.size()-1))))
			return false;
		}
	    }
	}
    }

    return true;
}

//undo a replacement from c -> key
void undo_letter(const string key, const char c, vector<vector<string>>& cipher = ::cipher)
{
    //add key count back
    ++(freq[c-97]);
    
    //number of replacements made
    while (numpos.top() != 0)
    {
	//replace position with key
	cipher[pos.top().first][pos.top().second] = key;

	pos.pop();
	numpos.top() -= 1;
    }

    numpos.pop();
}

void undo_word(vector<vector<string>>& cipher = ::cipher)
{
    //number of letters tried
    while (attempts.top() != 0)
    {
	//undo k -> c
	undo_letter(ops.top().first, ops.top().second, cipher);
	
	ops.pop();
	attempts.top() -= 1;
    }

    attempts.pop();
}

bool try_word(vector<string>& word, const string& str, bool plain = false, vector<vector<string>>& cipher = ::cipher)
{
    attempts.push(int(0));

    //try every letter
    for (int i = 0; i < word.size(); ++i)
    {
	//if key is undeciphered, try char
	if (isdigit(word[i][0]))
	{
	    //trying key and char
	    ops.push(pair<string, char>(word[i], str[i]));
	    
	    //keep track of number of letters tried
	    attempts.top() += 1;
	    
	    //if k -> c doesn't work, undo
	    if (!try_letter(word[i], str[i], plain,cipher ))
	    {
		undo_word(cipher);
		return false;
	    }
	}
	//if key is deciphered, check if it matches char
	else if (islower(word[i][0]))
	{
	    //no match, undo word
	    if (word[i][0] != str[i])
	    {
		undo_word(cipher);
		return false;
	    }
	}
    }
    return true;
}

//clear out deciphers done, resets cipher
void clear_ops()
{
    while (!attempts.empty())
	undo_word();
}

//try a known plaintext
bool try_plaintext(const string& plain)
{
    int word = 0;
    
    //tokenize plaintext
    stringstream line(plain);
    string token;
    while (line >> token)
    {
	//try each word
	if(!try_word(cipher[word], token, true))
	{
	    //undo everything on fail
	    set_freq();
	    clear_ops();
	    return false;
	}

	++word;
    }

    return true;
}

//perform deciphers on global cipher
void perform_ops()
{
    while (!ops.empty())
    {
	for (auto& vec : cipher)
	    for (auto& s : vec)
		if (s == ops.top().first)
		    s = ops.top().second;
	ops.pop();
    }
}

//get weight of a word; number of letters that will be deciphered on successful guess of word
int get_weight(const vector<string>& word)
{
    int weight = 0;
    for (auto& letter : word)
	weight += occurences[stoi(letter)];
    return weight;
}

//decryption using dictionary
pair<bool, string> try_dictionary(vector<vector<string>> cipher = ::cipher)
{
    //create a copy of the cipher we attempt to decrypt
    vector<vector<string>> ciphercp = cipher;
    
    //reorder the cipher copy (not including last word as it can be truncated) based on higher value words
    sort(ciphercp.begin(), ciphercp.end()-1, [](const vector<string>& a, const vector<string>& b) -> bool { return (dict[a.size()-1].size()/get_weight(a) < dict[b.size()-1].size()/get_weight(b)); });

    //maintain a stack to remember previous matches to go back to
    stack<pair<int, vector<string>>> prev_matches;

    bool attempt = true;

    //attempt decrytion using regular expressions and backtracking
    for (auto iter = ciphercp.begin(); iter != ciphercp.end(); ++iter) //for every word in cipher
    {
	int idx = 0;
	
	//a vector of strings that potentially match the cipher word
	vector<string> matches;
	
	//previous attempt failed, use previous matches
	if (!attempt)
	{
	    //restore index and matches
	    idx = prev_matches.top().first;
	    matches = prev_matches.top().second;

	    //undo failed word
	    undo_word(ciphercp);

	    //go to next word
	    ++idx;

	    prev_matches.pop();
	    attempt = true;
	}
	//find matches
	else
	{
	    //special case for last word
	    if (iter == ciphercp.end()-1)
	    {
		//total potential size
		int total_size = 0;
		for (int i = iter->size()-1; i < dict.size(); ++i)
		    total_size += dict[i].size();
		
		matches.resize(total_size);
		
		//search dictionary
		auto it = matches.begin();
		regex r(make_regex(*iter, true));
		for (int i = iter->size()-1; i < dict.size(); ++i)
		    it = copy_if(dict[i].begin(), dict[i].end(), it, [&] (const string& s) -> bool { return regex_match(s, r); });

		matches.resize(distance(matches.begin(), it));
	    }
	    else
	    {
		//make matches big enough to store everything to potentially store everything
		matches.resize(dict[iter->size()-1].size());
		
		//search dictionary for potential matches
		regex r(make_regex(*iter));
		auto it = copy_if(dict[iter->size()-1].begin(), dict[iter->size()-1].end(), matches.begin(), [&] (const string& s) -> bool { return regex_match(s, r); });
		
		matches.resize(distance(matches.begin(), it));
	    }
	}
	    	
	bool decrypted = false;

	//try the matches
	for (int i = idx; i < matches.size(); ++i)
	{
	    //match succeeds
	    if (try_word(*iter, matches[i], false, ciphercp))
	    {
		decrypted = true;
		
		//store matches
		prev_matches.push(pair<int, vector<string>>(i, matches));

		//move onto next cipher word
		break;
	    }
	}

	//no matches succeeded
	if (!decrypted)
	{
	    //set variable for backtracking
	    attempt = false;

	    //fix iterator and continue
	    if (iter != ciphercp.begin())
	    {
		iter -= 2;
		continue;
	    }
	    else
		//all matches for first cipher word failed, improper cipher
		return pair<bool, string>(false, "error: decryption not possible\n");
	}
	
	//check if cipher is completely decrypted
	if (check_cipher(ciphercp))
	    break;

	//otherwise a word succeeded, but ciphertext is not decrypted, continue on to next cipher word
    }
    
    //decryption complete
    
    //perform operations on main ciphertext
    perform_ops();
    
    //get back message
    string m = "";
    for (auto& vec : ::cipher)
    {
	for(auto& ch : vec)
	    m += ch;
	m +=  " ";
    }
    m += "\n";

    return pair<bool, string>(true, m);
}

//remove whitespaces
string trim_string(string& s)
{
    int start = s.find_first_not_of(" \t\n");
    int end = s.find_last_not_of(" \t\n");

    if (start != -1 && end !=-1)
	return s.substr(start, end - start + 1);

    return "";
}

int main(int argc, char* argv[])
{
    //getting things set up
    load_plaintexts();
    load_dictionary();

    while (true)    //loop forever
    {
	clear_stacks();	//reset all stacks
	set_freq();	//reset frequencies
	cipher.clear();	//reset cipher vector

	bool decrypted = false;

	//read from standard input
	cout << "Enter the ciphertext: ";
	string ciphertext;
	getline(cin, ciphertext);
	
	//line is empty
	if (trim_string(ciphertext).length() == 0)
	    continue;

	//analyzing and reassembling the ciphertext
	vector<int> chars = get_characters(ciphertext);

	for (size_t i = 0; i < plaintext_count.size(); ++i)
	{
	    //look for matches with plaintext
	    if (chars == plaintext_count[i])
	    {
		//find all possible plaintexts
		auto range = count_to_plaintext.equal_range(i);

		//attempt decryption using matches
		for (auto iter = range.first; iter != range.second; ++iter)
		{
		    if(try_plaintext(plaintexts[iter->second]))
		    {
			cout << "My plaintext guess is: " <<  plaintexts[iter->second] << "\n";
			decrypted = true;
			break;
		    }
		}

		if (decrypted)
		    break;
	    }
	}

	if (decrypted)
	    continue;
	
	//clear operations that were done
	clear_ops();
	
	//known plaintext decryption failed, trying dictionary
	pair<bool, string> result = try_dictionary();
	if (result.first)
	    cout << "My plaintext guess: " << result.second;
	else
	    cerr << result.second;
    }
    return 0;
}
