import java.util.*;

public class Solution {
    public static void main(String[] args) {
        
        Scanner sc = new Scanner(System.in);

        // number of food types
        int n = sc.nextInt();

        // maximum meals
        int m = sc.nextInt();

        // array v
        int[] v = new int[n];
        for(int i = 0; i < n; i++){
            v[i] = sc.nextInt();
        }

        // array d
        int[] d = new int[n];
        for(int i = 0; i < n; i++){
            d[i] = sc.nextInt();
        }
        PriorityQueue<int[]> pq=new PriorityQueue<>((a,b)->b[0]-a[0]);
        for(int i=0;i<n;i++){
            pq.add(new int[]{v[i],1});
        }
        for(int i=0;i<n;i++){
            
        }
    }
}