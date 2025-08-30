import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

// HackCracker - Shamir's Secret Sharing Solution
public class HackCracker {
    
    // Secret Point data structure
    private static class SecretPoint {
        final BigInteger xCoord;
        final BigInteger yCoord;
        final String rawBase;
        final String rawValue;
        final boolean isSuspicious;
        
        SecretPoint(BigInteger x, BigInteger y, String base, String val) {
            this.xCoord = x;
            this.yCoord = y;
            this.rawBase = base;
            this.rawValue = val;
            this.isSuspicious = false;
        }
        
        SecretPoint markAsSuspicious() {
            return new SecretPoint(this.xCoord, this.yCoord, this.rawBase, this.rawValue) {
                @Override
                public boolean isSuspicious() { return true; }
            };
        }
        
        public boolean isSuspicious() { return this.isSuspicious; }
        
        @Override
        public String toString() {
            return String.format("Point[x=%s, y=%s]", xCoord, yCoord);
        }
    }
    
    // Result storage class
    private static class CrackingResult {
        final BigInteger discoveredSecret;
        final Set<Integer> faultyPointIds;
        final double confidenceScore;
        final Map<String, Object> debugInfo;
        
        CrackingResult(BigInteger secret, Set<Integer> badPoints, double confidence) {
            this.discoveredSecret = secret;
            this.faultyPointIds = badPoints;
            this.confidenceScore = confidence;
            this.debugInfo = new HashMap<>();
        }
        
        CrackingResult withDebugInfo(String key, Object value) {
            this.debugInfo.put(key, value);
            return this;
        }
    }
    
    // Base conversion method
    private static BigInteger hackDecodeBase(String encodedValue, int baseSystem) {
        if (encodedValue == null || encodedValue.trim().isEmpty()) {
            throw new RuntimeException("Cannot decode empty value");
        }
        
        BigInteger result = BigInteger.ZERO;
        BigInteger multiplier = BigInteger.ONE;
        BigInteger base = BigInteger.valueOf(baseSystem);
        
        // Process from right to left
        for (int pos = encodedValue.length() - 1; pos >= 0; pos--) {
            char symbol = Character.toLowerCase(encodedValue.charAt(pos));
            int digitValue = getDigitValue(symbol, baseSystem);
            
            result = result.add(BigInteger.valueOf(digitValue).multiply(multiplier));
            multiplier = multiplier.multiply(base);
        }
        
        return result;
    }
    
    private static int getDigitValue(char symbol, int base) {
        int value;
        if (symbol >= '0' && symbol <= '9') {
            value = symbol - '0';
        } else if (symbol >= 'a' && symbol <= 'z') {
            value = symbol - 'a' + 10;
        } else {
            throw new RuntimeException("Invalid character: '" + symbol + "'");
        }
        
        if (value >= base) {
            throw new RuntimeException("Invalid digit for base " + base);
        }
        
        return value;
    }
    
    // Lagrange interpolation method
    private static BigInteger crackSecretWithLagrange(List<SecretPoint> validPoints) {
        if (validPoints.size() < 2) {
            throw new RuntimeException("Need at least 2 points");
        }
        
        BigInteger secretValue = BigInteger.ZERO;
        
        for (int i = 0; i < validPoints.size(); i++) {
            BigInteger currentTerm = validPoints.get(i).yCoord;
            
            for (int j = 0; j < validPoints.size(); j++) {
                if (i == j) continue;
                
                BigInteger xi = validPoints.get(i).xCoord;
                BigInteger xj = validPoints.get(j).xCoord;
                
                BigInteger numerator = xj.negate();
                BigInteger denominator = xi.subtract(xj);
                
                if (denominator.equals(BigInteger.ZERO)) {
                    throw new RuntimeException("Duplicate x-coordinates detected");
                }
                
                currentTerm = currentTerm.multiply(numerator).divide(denominator);
            }
            
            secretValue = secretValue.add(currentTerm);
        }
        
        return secretValue;
    }
    
    // Generate k-combinations
    private static <T> List<List<T>> generateCombos(List<T> items, int pickCount) {
        List<List<T>> allCombos = new ArrayList<>();
        buildCombosRecursively(items, pickCount, 0, new ArrayList<>(), allCombos);
        return allCombos;
    }
    
    private static <T> void buildCombosRecursively(List<T> items, int needed, 
            int startIdx, List<T> current, List<List<T>> results) {
        if (current.size() == needed) {
            results.add(new ArrayList<>(current));
            return;
        }
        
        for (int i = startIdx; i <= items.size() - (needed - current.size()); i++) {
            current.add(items.get(i));
            buildCombosRecursively(items, needed, i + 1, current, results);
            current.remove(current.size() - 1);
        }
    }
    
    // Main secret finding algorithm
    private static CrackingResult hackTheSecret(List<SecretPoint> allPoints, int threshold) {
        List<List<SecretPoint>> possibleCombos = generateCombos(allPoints, threshold);
        Map<BigInteger, List<List<SecretPoint>>> secretCandidates = new HashMap<>();
        
        // Try each combination
        int successfulCracks = 0;
        for (List<SecretPoint> combo : possibleCombos) {
            try {
                BigInteger potentialSecret = crackSecretWithLagrange(combo);
                secretCandidates.computeIfAbsent(potentialSecret, k -> new ArrayList<>()).add(combo);
                successfulCracks++;
            } catch (Exception e) {
                // Some combinations might fail
                continue;
            }
        }
        
        // Find the most frequent secret
        BigInteger winningSecret = null;
        int maxOccurrences = 0;
        List<List<SecretPoint>> winningCombos = null;
        
        for (Map.Entry<BigInteger, List<List<SecretPoint>>> entry : secretCandidates.entrySet()) {
            if (entry.getValue().size() > maxOccurrences) {
                maxOccurrences = entry.getValue().size();
                winningSecret = entry.getKey();
                winningCombos = entry.getValue();
            }
        }
        
        // Identify suspicious points
        Set<Integer> goodPointIds = new HashSet<>();
        Set<Integer> allPointIds = allPoints.stream()
            .map(p -> p.xCoord.intValue())
            .collect(Collectors.toSet());
            
        if (winningCombos != null) {
            for (List<SecretPoint> combo : winningCombos) {
                for (SecretPoint point : combo) {
                    goodPointIds.add(point.xCoord.intValue());
                }
            }
        }
        
        Set<Integer> suspiciousPointIds = allPointIds.stream()
            .filter(id -> !goodPointIds.contains(id))
            .collect(Collectors.toSet());
        
        double confidence = successfulCracks > 0 ? 
            (double) maxOccurrences / successfulCracks : 0.0;
        
        return new CrackingResult(winningSecret, suspiciousPointIds, confidence)
            .withDebugInfo("totalCombinations", possibleCombos.size())
            .withDebugInfo("successfulCracks", successfulCracks)
            .withDebugInfo("consensusCount", maxOccurrences);
    }
    
    // Main solver method
    public static CrackingResult solveChallengeCase(Map<String, Object> challengeData) {
        // Parse the challenge metadata
        @SuppressWarnings("unchecked")
        Map<String, Integer> config = (Map<String, Integer>) challengeData.get("keys");
        int totalShares = config.get("n");
        int requiredShares = config.get("k");
        
        // Parse all the secret points
        List<SecretPoint> decodedPoints = new ArrayList<>();
        
        for (String key : challengeData.keySet()) {
            if (key.equals("keys")) continue;
            
            @SuppressWarnings("unchecked")
            Map<String, String> pointData = (Map<String, String>) challengeData.get(key);
            
            try {
                BigInteger x = new BigInteger(key);
                int base = Integer.parseInt(pointData.get("base"));
                String encodedY = pointData.get("value");
                BigInteger y = hackDecodeBase(encodedY, base);
                
                SecretPoint point = new SecretPoint(x, y, pointData.get("base"), encodedY);
                decodedPoints.add(point);
            } catch (Exception e) {
                continue;
            }
        }
        
        // Crack the secret
        CrackingResult result = hackTheSecret(decodedPoints, requiredShares);
        return result;
    }
    
    public static void main(String[] args) {
        // Test cases
        Map<String, Object> challenge1 = buildTestCase1();
        Map<String, Object> challenge2 = buildTestCase2();
        
        // Solve both challenges
        CrackingResult result1 = solveChallengeCase(challenge1);
        CrackingResult result2 = solveChallengeCase(challenge2);
        
        // Output results
        System.out.println("TestCase-1 Secret: " + result1.discoveredSecret);
        System.out.println("TestCase-2 Secret: " + result2.discoveredSecret);
        System.out.println("TestCase-1 Wrong Points: " + 
            (result1.faultyPointIds.isEmpty() ? "None" : result1.faultyPointIds));
        System.out.println("TestCase-2 Wrong Points: " + 
            (result2.faultyPointIds.isEmpty() ? "None" : result2.faultyPointIds));
    }
    
    // Test case 1 builder
    private static Map<String, Object> buildTestCase1() {
        Map<String, Object> testCase = new HashMap<>();
        
        Map<String, Integer> config = new HashMap<>();
        config.put("n", 4);
        config.put("k", 3);
        testCase.put("keys", config);
        
        // Point data
        String[][] pointsData = {
            {"1", "10", "4"},
            {"2", "2", "111"},
            {"3", "10", "12"},
            {"6", "4", "213"}
        };
        
        for (String[] data : pointsData) {
            Map<String, String> point = new HashMap<>();
            point.put("base", data[1]);
            point.put("value", data[2]);
            testCase.put(data[0], point);
        }
        
        return testCase;
    }
    
    // Test case 2 builder
    private static Map<String, Object> buildTestCase2() {
        Map<String, Object> testCase = new HashMap<>();
        
        Map<String, Integer> config = new HashMap<>();
        config.put("n", 10);
        config.put("k", 7);
        testCase.put("keys", config);
        
        // Test case 2 data
        String[][] megaPointsData = {
            {"1", "6", "13444211440455345511"},
            {"2", "15", "aed7015a346d635"},
            {"3", "15", "6aeeb69631c227c"},
            {"4", "16", "e1b5e05623d881f"},
            {"5", "8", "316034514573652620673"},
            {"6", "3", "2122212201122002221120200210011020220200"},
            {"7", "3", "20120221122211000100210021102001201112121"},
            {"8", "6", "20220554335330240002224253"},
            {"9", "12", "45153788322a1255483"},
            {"10", "7", "1101613130313526312514143"}
        };
        
        for (String[] data : megaPointsData) {
            Map<String, String> point = new HashMap<>();
            point.put("base", data[1]);
            point.put("value", data[2]);
            testCase.put(data[0], point);
        }
        
        return testCase;
    }
}