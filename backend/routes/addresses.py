import logging
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, get_dict_cursor, is_mysql

addresses_bp = Blueprint('addresses', __name__, url_prefix='/addresses')

@addresses_bp.route("", methods=["GET"])
@jwt_required()
def get_addresses():
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user identity"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("""
            SELECT id, user_id, full_name, phone, street_address, 
                   city, state, postal_code, country, is_default, created_at
            FROM addresses
            WHERE user_id = %s
            ORDER BY is_default DESC, id DESC
        """, (user_id,))
        rows = cursor.fetchall()
        addresses = []
        for r in rows:
            addresses.append({
                "id": r["id"],
                "full_name": r["full_name"],
                "phone": r["phone"],
                "street_address": r["street_address"],
                "city": r["city"],
                "state": r["state"] or "",
                "postal_code": r["postal_code"],
                "country": r["country"] or "USA",
                "is_default": bool(r["is_default"]),
                "created_at": str(r["created_at"]) if r.get("created_at") else None
            })

        return jsonify({"success": True, "addresses": addresses}), 200
    except Exception as e:
        logging.error(f"Error fetching addresses: {e}")
        return jsonify({"success": False, "error": "Failed to fetch addresses"}), 500
    finally:
        cursor.close()
        conn.close()

@addresses_bp.route("", methods=["POST"])
@jwt_required()
def add_address():
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user identity"}), 401

    data = request.get_json(silent=True) or {}
    full_name = data.get("full_name", "").strip()
    phone = data.get("phone", "").strip()
    street_address = data.get("street_address", "").strip()
    city = data.get("city", "").strip()
    state = data.get("state", "").strip()
    postal_code = data.get("postal_code", "").strip()
    country = data.get("country", "USA").strip() or "USA"
    is_default = bool(data.get("is_default", False))

    if not full_name or not phone or not street_address or not city or not postal_code:
        return jsonify({
            "success": False, 
            "error": "Full name, phone, street address, city, and postal code are required"
        }), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Check if user already has addresses
        cursor.execute("SELECT COUNT(*) as count FROM addresses WHERE user_id = %s", (user_id,))
        res = cursor.fetchone()
        count = res["count"] if isinstance(res, dict) else res[0]

        # If this is the user's first address, make it default automatically
        if count == 0:
            is_default = True
        elif is_default:
            cursor.execute("UPDATE addresses SET is_default = FALSE WHERE user_id = %s", (user_id,))

        cursor.execute("""
            INSERT INTO addresses (user_id, full_name, phone, street_address, city, state, postal_code, country, is_default)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, full_name, phone, street_address, city, state, postal_code, country, is_default))

        new_id = cursor.lastrowid if is_mysql(conn) else None
        if not new_id:
            cursor.execute("SELECT id FROM addresses WHERE user_id = %s ORDER BY id DESC LIMIT 1", (user_id,))
            new_id = cursor.fetchone()["id"]

        conn.commit()
        return jsonify({
            "success": True, 
            "message": "Delivery address added successfully",
            "address": {
                "id": new_id,
                "full_name": full_name,
                "phone": phone,
                "street_address": street_address,
                "city": city,
                "state": state,
                "postal_code": postal_code,
                "country": country,
                "is_default": is_default
            }
        }), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Error adding address: {e}")
        return jsonify({"success": False, "error": "Failed to add address"}), 500
    finally:
        cursor.close()
        conn.close()

@addresses_bp.route("/<int:address_id>", methods=["PUT"])
@jwt_required()
def update_address(address_id):
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user identity"}), 401

    data = request.get_json(silent=True) or {}
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # IDOR protection: ensure the address belongs to the authenticated user
        cursor.execute("SELECT id FROM addresses WHERE id = %s AND user_id = %s", (address_id, user_id))
        if not cursor.fetchone():
            return jsonify({"success": False, "error": "Address not found or unauthorized"}), 404

        full_name = data.get("full_name")
        phone = data.get("phone")
        street_address = data.get("street_address")
        city = data.get("city")
        state = data.get("state")
        postal_code = data.get("postal_code")
        country = data.get("country")
        is_default = data.get("is_default")

        updates = []
        params = []

        if full_name is not None:
            updates.append("full_name = %s")
            params.append(full_name.strip())
        if phone is not None:
            updates.append("phone = %s")
            params.append(phone.strip())
        if street_address is not None:
            updates.append("street_address = %s")
            params.append(street_address.strip())
        if city is not None:
            updates.append("city = %s")
            params.append(city.strip())
        if state is not None:
            updates.append("state = %s")
            params.append(state.strip())
        if postal_code is not None:
            updates.append("postal_code = %s")
            params.append(postal_code.strip())
        if country is not None:
            updates.append("country = %s")
            params.append(country.strip())
        if is_default is not None:
            bool_default = bool(is_default)
            if bool_default:
                cursor.execute("UPDATE addresses SET is_default = FALSE WHERE user_id = %s", (user_id,))
            updates.append("is_default = %s")
            params.append(bool_default)

        if updates:
            params.extend([address_id, user_id])
            cursor.execute(f"UPDATE addresses SET {', '.join(updates)} WHERE id = %s AND user_id = %s", tuple(params))
            conn.commit()

        return jsonify({"success": True, "message": "Address updated successfully"}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error updating address: {e}")
        return jsonify({"success": False, "error": "Failed to update address"}), 500
    finally:
        cursor.close()
        conn.close()

@addresses_bp.route("/<int:address_id>", methods=["DELETE"])
@jwt_required()
def delete_address(address_id):
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user identity"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # IDOR protection
        cursor.execute("SELECT id, is_default FROM addresses WHERE id = %s AND user_id = %s", (address_id, user_id))
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Address not found or unauthorized"}), 404

        was_default = bool(row["is_default"])
        cursor.execute("DELETE FROM addresses WHERE id = %s AND user_id = %s", (address_id, user_id))

        # If deleted address was default, promote another address to default
        if was_default:
            cursor.execute("SELECT id FROM addresses WHERE user_id = %s ORDER BY id DESC LIMIT 1", (user_id,))
            other = cursor.fetchone()
            if other:
                cursor.execute("UPDATE addresses SET is_default = TRUE WHERE id = %s", (other["id"],))

        conn.commit()
        return jsonify({"success": True, "message": "Address deleted successfully"}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error deleting address: {e}")
        return jsonify({"success": False, "error": "Failed to delete address"}), 500
    finally:
        cursor.close()
        conn.close()

@addresses_bp.route("/<int:address_id>/default", methods=["PATCH"])
@jwt_required()
def set_default_address(address_id):
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user identity"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # IDOR protection
        cursor.execute("SELECT id FROM addresses WHERE id = %s AND user_id = %s", (address_id, user_id))
        if not cursor.fetchone():
            return jsonify({"success": False, "error": "Address not found or unauthorized"}), 404

        cursor.execute("UPDATE addresses SET is_default = FALSE WHERE user_id = %s", (user_id,))
        cursor.execute("UPDATE addresses SET is_default = TRUE WHERE id = %s AND user_id = %s", (address_id, user_id))
        conn.commit()

        return jsonify({"success": True, "message": "Default delivery address updated"}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error setting default address: {e}")
        return jsonify({"success": False, "error": "Failed to set default address"}), 500
    finally:
        cursor.close()
        conn.close()
