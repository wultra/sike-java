/*
 * Copyright 2020 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.wultra.security.pqc.sike.kat.model;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * Class representing a KAT response file.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class KatRspFile {

    private final List<KatRspRecord> katRecords = new ArrayList<>();

    /**
     * KAT file constructor.
     * @param file File to read.
     */
    public KatRspFile(File file) throws FileNotFoundException {
        readFile(file);
    }

    /**
     * Get parsed KAT records.
     * @return KAT records.
     */
    public List<KatRspRecord> getKatRecords() {
        return katRecords;
    }

    /**
     * Add a KAT record.
     * @param katRecord KAT record.
     */
    public void add(KatRspRecord katRecord) {
        katRecords.add(katRecord);
    }

    /**
     * Read the KAT response file.
     * @throws FileNotFoundException Thrown when file is not found.
     */
    private void readFile(File file) throws FileNotFoundException {
        Scanner scanner = new Scanner(file);
        KatRspRecord record = new KatRspRecord();
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();
            if (!line.contains(" = ")) {
                continue;
            }
            String[] parts = line.split(" = ");
            if (parts.length != 2) {
                continue;
            }
            String key = parts[0];
            String value = parts[1];
            switch(key) {
                case "count":
                    record = new KatRspRecord();
                    record.setCount(Integer.parseInt(value));
                    break;
                case "seed":
                    record.setSeed(value);
                    break;
                case "pk":
                    record.setPk(value);
                    break;
                case "sk":
                    record.setSk(value);
                    break;
                case "ct":
                    record.setCt(value);
                    break;
                case "ss":
                    record.setSs(value);
                    add(record);
                    break;
            }
        }
    }

}
