using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace PacketParser.CleartextDictionary {
    //http://en.wikipedia.org/wiki/Bloom_filter
    public class BloomFilter {
        private BitArray bitArray;
        private int nHashFunctions;
        private int indexMask;
        private long wordCount;
        private int tmpStatFilledValues=0;

        public long WordCount { get { return this.wordCount; } }

        public BloomFilter(ICollection<string> wordList) {
            this.wordCount = 0;
            //to acheive 1% error we need "array size"/"#elements" = 9.6
            int indexValueBits=0;
            //while(1<<indexValueBits < 9.6*wordList.Count)
            while(1<<indexValueBits < 15*wordList.Count)//14*wordList.Count gives 0.1% of false positives
                indexValueBits++;
            indexValueBits++;//since we started with one bit...
            int indexSize=1<<(indexValueBits-1);
            this.indexMask=indexSize-1;

            this.bitArray=new BitArray(indexSize, false);//2^24 bits = 16MByte
            if (wordList.Count == 0)
                this.nHashFunctions = 1;
            else
                this.nHashFunctions=(int)(0.7*indexSize/(wordList.Count));

            foreach(string s in wordList)
                this.AddWord(s);
            for(int i=0; i<bitArray.Length; i++)
                if(this.bitArray[i])
                    this.tmpStatFilledValues++;
        }

        public bool HasWord(string word) {
            int[] indexes= this.GetIndexes(word);
            foreach(int index in indexes)
                if(!this.bitArray[index])
                    return false;
            return true;
        }

        private int[] GetIndexes(string word) {
            int[] indexes=new int[nHashFunctions];

            //simple hash method
            for(int i=0; i<indexes.Length; i++) {
                int hash=(word+i.ToString()).GetHashCode();
                indexes[i] = (hash * i * 7) & this.indexMask;
            }
            return indexes;
        }

        private void AddWord(string word) {
            word=word.ToLower();
            int[] indexes= this.GetIndexes(word);
            foreach(int index in indexes)
                this.bitArray[index]=true;
            this.wordCount++;


        }


    }
}
