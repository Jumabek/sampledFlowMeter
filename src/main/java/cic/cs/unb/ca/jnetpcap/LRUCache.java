package cic.cs.unb.ca.jnetpcap;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;

import java.util.HashMap;

import org.apache.logging.log4j.core.util.SystemClock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


class Entry {
    BasicFlow value;
    String key;
    Entry left;
    Entry right;
}

public class LRUCache {
    public static final Logger logger = LoggerFactory.getLogger(LRUCache.class);
    HashMap<String, Entry> hashmap;
    Entry start=null, end=null;
    long LRU_SIZE ;
    public long lastFlushTime = 0;
    public long num_flushes=0;

    // implementation, it can make be dynamic
    public LRUCache(long cache_size) {
        LRU_SIZE = cache_size;
        hashmap = new HashMap<String, Entry>();
    }

    public long getNumberOfItems(){
        return this.hashmap.size();
    }
    public boolean containsKey(String key){
        return hashmap.containsKey(key);
    }

    public Set<String> getKeySet(){
        return hashmap.keySet();
    }

    public BasicFlow getEntry(String key) {
        if (hashmap.containsKey(key)) // Key Already Exist, just update the
        {
            Entry entry = hashmap.get(key);
            removeNode(entry);
            addAtTop(entry);
            return entry.value;
        }
        return null;
    }

    public void removeEntry(String key) {
        if (hashmap.containsKey(key)) // Key Already Exist, just update the
        {
            Entry entry = hashmap.get(key);
            removeNode(entry);
            hashmap.remove(key);
        }
        else{
            System.out.println("Attempt to remove non existing entry from cache\n");
            int a = 1/0;
        }
    }

    public BasicFlow putEntry(String key, BasicFlow flow, long currentTimestamp, long flowTimeOut) {
        BasicFlow flowToBeKicked=null;
        if (hashmap.containsKey(key)) // Key Already Exist, just update the value and move it to top
        {
            Entry entry = hashmap.get(key);
            entry.value = flow;
            removeNode(entry);
            addAtTop(entry);
        } else {
            Entry newnode = new Entry();
            newnode.left = null;
            newnode.right = null;
            newnode.value = flow;
            newnode.key = key;
            if (hashmap.size() > LRU_SIZE) // We have reached maxium size so need to make room for new element.
            {
                hashmap.remove(end.key);
                flowToBeKicked = end.value;
                removeNode(end);
            }

            addAtTop(newnode);
            hashmap.put(key, newnode);
        }
        return flowToBeKicked;
    }

    public void addAtTop(Entry node) {
        node.right = start;
        node.left = null;
        if (start != null)
            start.left = node;
        start = node;
        if (end == null)
            end = start;
    }

    public void removeNode(Entry node) {

        if (node.left != null) {
            node.left.right = node.right;
        } else {
            start = node.right;
        }

        if (node.right != null) {
            node.right.left = node.left;
        } else {
            end = node.left;
        }
    }



    public long getNumOfConcurrentFlows(long currentTimeStamp, long concurrentFlowWindow){
        Entry ptr = start;
        long num_concurrent_flows= 0;

        if(ptr==null) return 0;
        //System.out.println("Getting #CF");
        while(currentTimeStamp - ptr.value.getLastSeen() < concurrentFlowWindow){
            num_concurrent_flows++;
            ptr = ptr.right;

            if (ptr==null) break;
        }
        return num_concurrent_flows;
    }


    //does not affect results, only helps improve performance by flushing the table for TimedOutFLows
    public ArrayList<BasicFlow> flushTable(long currentTimestamp, long flowTimeout){
        ArrayList<BasicFlow> record_list = new ArrayList<BasicFlow>();
        long firstSeen;
        if (end==null){return record_list;} //means empty
        num_flushes++;

        Entry ptr = end;// starting from end check for flowtimeout and remove
        while(ptr!=null){
            firstSeen = ptr.value.getFlowStartTime();
            if (currentTimestamp-firstSeen >= flowTimeout){
                //System.out.println(String.format("%s: %d - %d >= %d".format(ptr.key,currentTimestamp,firstSeen,flowTimeout)));
                record_list.add(ptr.value);
                removeEntry(ptr.key);
                ptr = end; //because end is updated now
            }
            else{
                ptr = ptr.left;
            }

        }
        this.lastFlushTime = currentTimestamp;
        return record_list;

    }

}
