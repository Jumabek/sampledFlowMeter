package cic.cs.unb.ca.jnetpcap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;


public class QueueAssistedLRUCache {
    public static final Logger logger = LoggerFactory.getLogger(LRUCache.class);

    HashMap<String, Entry> hashmap;
    Entry start=null, end=null;
    long LRU_SIZE ;

    public long lastFlushTime = 0;
    public long num_flushes=0;

    Queue<Entry> queue = new LinkedList<>();

    // implementation, capacity can be made dynamic too
    public QueueAssistedLRUCache(long cache_size) {
        LRU_SIZE = cache_size;
        hashmap = new HashMap<String, Entry>();
    }

    public long getNumberOfItems(){
        return this.hashmap.size();
    }

    public boolean containsKey(String key){
        return hashmap.containsKey(key);
    }

    //Called from LRUCachedFlowGenerator
    public Set<String> getKeySet(){
        return hashmap.keySet();
    }


    public void addAtTop(Entry node) { // adds updated/newly-added entry at the top of cache
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


    public BasicFlow getEntry(String key) { // If Key Already Exist, just update the order
        if (hashmap.containsKey(key))
        {
            Entry entry = hashmap.get(key);
            removeNode(entry);
            addAtTop(entry);
            return entry.value;
        }
        return null;
    }


    public void removeEntry(String key) { //remove from tree, queue, hashmap
        if (hashmap.containsKey(key))
        {
            Entry entry = hashmap.get(key);
            removeNode(entry);
            queue.remove(entry);
            hashmap.remove(key);
        }
        else{
            System.out.println("Attempt to remove non existing entry from cache\n");
            int a = 1/0;
        }
    }


    public BasicFlow putEntry(String key, BasicFlow flow) {
        BasicFlow flowToBeKicked=null;
        if (hashmap.containsKey(key)) // Key Already Exist, just update the value and move it to top
        {
            Entry entry = hashmap.get(key);
            entry.value = flow;

            removeNode(entry);
            addAtTop(entry);
        } else {//make new entry and put
            //if full, make space
            if (hashmap.size() > LRU_SIZE) // We have reached maxium size so need to make room for new element.
            {
                flowToBeKicked = end.value;
                removeEntry(end.key);
            }

            //construct new entry
            Entry newnode = new Entry();
            newnode.left = null;
            newnode.right = null;
            newnode.value = flow;
            newnode.key = key;

            //now put new entry
            addAtTop(newnode);
            queue.add(newnode); // only needed once for Flow start time
            hashmap.put(key, newnode);
        }
        return flowToBeKicked;
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


    //does not affect #records, 1) helps improve extraction performance by flushing the table. 2) gives accurate WSAF count (eg. per second)
    public ArrayList<BasicFlow> flushTable(long currentTimestamp, long flowTimeout, long idleTimeout){
        ArrayList<BasicFlow> record_list = new ArrayList<BasicFlow>();
        num_flushes++;

        // expiry due to active flow timeout
        while(!queue.isEmpty()){
            Entry ptr = queue.element(); // start from the beginnin(earliest flow) // *.element returns element at start w/o deleting
            if (currentTimestamp-ptr.value.getFlowStartTime() >= flowTimeout){
                record_list.add(ptr.value);
                removeEntry(ptr.key);
            }
            else{//bcause others are newer than last one
                break;
            }
        }

        // expiry due to idle timeout
        Entry ptr = end;
        while (ptr!=null){
            if (currentTimestamp - ptr.value.getLastSeen() >= idleTimeout){
                record_list.add(ptr.value);
                removeEntry(ptr.key);
            }
            else{//bcause others are newer than last one
                break;
            }
            ptr = ptr.left;
        }

        this.lastFlushTime = currentTimestamp;
        return record_list;
    }

}
